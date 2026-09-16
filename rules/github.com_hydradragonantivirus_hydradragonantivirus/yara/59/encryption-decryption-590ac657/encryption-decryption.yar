rule Encryption_Decryption {
 	meta:
		mitre = "T1027 Obfucated File or Information, T1140 Deobfuscate/Decode Files, T1573 Encrypted Channel: Asymmetric Cryptography"
 	strings:
		$aes = "aes_decrypt"
       		$a = "openssl enc"
		$b = "openssl md5"
		$c = "-base64 -d"
		$d = "-base64 -out"
		$e = "aes-256-cbc"
		$o = "/usr/bin/openssl"
		$AES = "aes_decrypt" base64
       		$A = "openssl enc" base64
		$B = "openssl md5" base64
		$C = "-base64 -d" base64
		$D = "-base64 -out" base64
		$E = "aes-256-cbc" base64
		$O = "/usr/bin/openssl" base64
   	condition:
 		any of them
}