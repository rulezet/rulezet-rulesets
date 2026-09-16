rule WEBSHELL_PHP_Generic_Closure_Invoke : hardened limited
{
	meta:
		description = "PHP webshell reconstruct of a callable function for execution on user input"
		author = "Arnim Rupp modified by OPSWAT"
		hash = "856beff7281e884c4c6e6ee98edbfd4c2e76f9372c8426f30f1681e0553f85ee"
		score = 75

	strings:
		$closure_invoke = /Closure::fromCallable\((["'][^"']+["']|\$[A-Za-z_][A-Za-z0-9_]*)\)\s*->\s*__invoke\(\s*{?\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ wide ascii
		$gfp1 = {65 76 61 6c 28 22 72 65 74 75 72 6e 20 5b 24 73 65 72 69 61 6c 69 73 65 64 5f 70 61 72 61 6d 65 74 65 72}
		$gfp2 = {24 74 68 69 73 2d 3e 61 73 73 65 72 74 28 73 74 72 70 6f 73 28 24 73 74 79 6c 65 73 2c 20 24}
		$gfp3 = {24 6d 6f 64 75 6c 65 20 3d 20 6e 65 77 20 24 5f 47 45 54 5b 27 6d 6f 64 75 6c 65 27 5d 28 24 5f 47 45 54 5b 27 73 63 6f 70 65 27 5d 29 3b}
		$gfp4 = {24 70 6c 75 67 69 6e 2d 3e 24 5f 50 4f 53 54 5b 27 61 63 74 69 6f 6e 27 5d 28 24 5f 50 4f 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp5 = {24 5f 50 4f 53 54 5b 70 61 72 74 69 74 69 6f 6e 5f 62 79 5d 28 24 5f 50 4f 53 54 5b}
		$gfp6 = {24 6f 62 6a 65 63 74 20 3d 20 6e 65 77 20 24 5f 52 45 51 55 45 53 54 5b 27 74 79 70 65 27 5d 28 24 5f 52 45 51 55 45 53 54 5b 27 69 64 27 5d 29 3b}
		$gfp7 = {54 68 65 20 61 62 6f 76 65 20 65 78 61 6d 70 6c 65 20 63 6f 64 65 20 63 61 6e 20 62 65 20 65 61 73 69 6c 79 20 65 78 70 6c 6f 69 74 65 64 20 62 79 20 70 61 73 73 69 6e 67 20 69 6e 20 61 20 73 74 72 69 6e 67 20 73 75 63 68 20 61 73}
		$gfp8 = {53 6d 61 72 74 79 5f 49 6e 74 65 72 6e 61 6c 5f 44 65 62 75 67 3a 3a 73 74 61 72 74 5f 72 65 6e 64 65 72 28 24 5f 74 65 6d 70 6c 61 74 65 29 3b}
		$gfp9 = {3f 70 34 79 6c 30 34 64 3d 55 4e 49 4f 4e 25 32 30 53 45 4c 45 43 54 25 32 30 27 3c 3f 25 32 30 73 79 73 74 65 6d 28 24 5f 47 45 54 5b 27 63 6f 6d 6d 61 6e 64 27 5d 29 3b 25 32 30 3f 3e 27 2c 32 2c 33 25 32 30 49 4e 54 4f 25 32 30 4f 55 54 46 49 4c 45 25 32 30 27 2f 76 61 72 2f 77 77 77 2f 77 33 62 73 68 33 6c 6c 2e 70 68 70}
		$gfp10 = {5b 5d 5b 7d 7b 3b 7c 5d 5c 7c 5c 5c 5b 2b 3d 5d 5c 7c 3c 3f 3d 3e 3f}
		$gfp11 = {28 65 76 61 6c 20 28 67 65 74 65 6e 76 20 22 45 50 52 4f 4c 4f 47 22 29 29 29}
		$gfp12 = {5a 6d 6c 73 5a 56 39 6e 5a 58 52 66 59 32 39 75 64 47 56 75 64 48 4d 6f 4a 32 68 30 64 48 41 36 4c 79 39 73 61 57 4e 6c 62 6e 4e 6c 4c 6d 39 77 5a 57 35 6a 59 58 4a 30 4c 57 46 77 61 53 35 6a 62 32 30 76 62 47 6c 6a 5a 57 35 7a 5a 53 35 77 61 48 41 2f 62 33 4a 6b 5a 58 4a}
		$php_short = {((3c 3f) | (3c 00 3f 00))}
		$no_xml1 = {((3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e) | (3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$no_xml2 = {((3c 3f 78 6d 6c 2d 73 74 79 6c 65 73 68 65 65 74) | (3c 00 3f 00 78 00 6d 00 6c 00 2d 00 73 00 74 00 79 00 6c 00 65 00 73 00 68 00 65 00 65 00 74 00))}
		$no_asp1 = {((3c 25 40 4c 41 4e 47 55 41 47 45) | (3c 00 25 00 40 00 4c 00 41 00 4e 00 47 00 55 00 41 00 47 00 45 00))}
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = {3c 3f 78 70 61 63 6b 65 74}
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = {((3c 3f 70 68 70) | (3c 00 3f 00 70 00 68 00 70 00))}
		$php_new3 = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 70 68 70) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 22 00 70 00 68 00 70 00))}

	condition:
		not ( any of ( $gfp* ) ) and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( $closure_invoke ) and filesize < 400
}