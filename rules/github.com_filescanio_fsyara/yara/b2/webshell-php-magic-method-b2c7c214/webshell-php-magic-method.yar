rule WEBSHELL_PHP_Magic_Method : hardened limited
{
	meta:
		description = "PHP webshell ultilize magic method"
		author = "Arnim Rupp modified by OPSWAT"
		hash = "fe07af4384f079a92fcc6fafad3821823b17c941b18523fc59ab53d55db3a4ec"
		score = 50

	strings:
		$magic_method1 = {((5f 5f 63 6f 6e 73 74 72 75 63 74) | (5f 00 5f 00 63 00 6f 00 6e 00 73 00 74 00 72 00 75 00 63 00 74 00))}
		$magic_method2 = {((5f 5f 64 65 73 74 72 75 63 74) | (5f 00 5f 00 64 00 65 00 73 00 74 00 72 00 75 00 63 00 74 00))}
		$magic_method3 = {((5f 5f 77 61 6b 65 75 70) | (5f 00 5f 00 77 00 61 00 6b 00 65 00 75 00 70 00))}
		$magic_method4 = {((5f 5f 63 61 6c 6c) | (5f 00 5f 00 63 00 61 00 6c 00 6c 00))}
		$magic_method5 = {((5f 5f 63 61 6c 6c 53 74 61 74 69 63) | (5f 00 5f 00 63 00 61 00 6c 00 6c 00 53 00 74 00 61 00 74 00 69 00 63 00))}
		$magic_method6 = {((5f 5f 73 6c 65 65 70) | (5f 00 5f 00 73 00 6c 00 65 00 65 00 70 00))}
		$magic_method7 = {((5f 5f 69 6e 76 6f 6b 65) | (5f 00 5f 00 69 00 6e 00 76 00 6f 00 6b 00 65 00))}
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
		$inp1 = {((70 68 70 3a 2f 2f 69 6e 70 75 74) | (70 00 68 00 70 00 3a 00 2f 00 2f 00 69 00 6e 00 70 00 75 00 74 00))}
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp8 = /\(\s?\$_HEADERS\s?[\)\[]/ wide ascii
		$inp15 = {((5f 53 45 52 56 45 52 5b 27 48 54 54 50 5f) | (5f 00 53 00 45 00 52 00 56 00 45 00 52 00 5b 00 27 00 48 00 54 00 54 00 50 00 5f 00))}
		$inp16 = {((5f 53 45 52 56 45 52 5b 22 48 54 54 50 5f) | (5f 00 53 00 45 00 52 00 56 00 45 00 52 00 5b 00 22 00 48 00 54 00 54 00 50 00 5f 00))}
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = {((61 72 72 61 79 5f 76 61 6c 75 65 73 28 24 5f 53 45 52 56 45 52 29) | (61 00 72 00 72 00 61 00 79 00 5f 00 76 00 61 00 6c 00 75 00 65 00 73 00 28 00 24 00 5f 00 53 00 45 00 52 00 56 00 45 00 52 00 29 00))}
		$inp19 = /file_get_contents\("https?:\/\// wide ascii
		$inp20 = {((54 53 4f 50 5f) | (54 00 53 00 4f 00 50 00 5f 00))}
		$inp21 = /array\(\'(_POST|_GET|_REQUEST)\'\)/ wide ascii
		$cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii
		$cpayload23 = /\bReflectionClass[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
		$m_cpayload_preg_filter2 = {((27 7c 2e 2a 7c 65 27) | (27 00 7c 00 2e 00 2a 00 7c 00 65 00 27 00))}

	condition:
		not ( any of ( $gfp* ) ) and ( ( ( $php_short in ( 0 .. 100 ) or $php_short in ( filesize - 1000 .. filesize ) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( any of ( $inp* ) ) and ( any of ( $cpayload* ) or all of ( $m_cpayload_preg_filter* ) ) and ( any of ( $magic_method* ) )
}