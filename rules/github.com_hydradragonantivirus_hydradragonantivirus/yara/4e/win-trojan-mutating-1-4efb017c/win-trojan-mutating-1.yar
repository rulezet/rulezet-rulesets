rule Win_Trojan_Mutating_1
{
strings:
	$a0 = { ee0c018beeb963022e8ab60501be4a0103f52e8a2432e62e882446e2f5be4a01bf4a01 }


condition:
	$a0
}