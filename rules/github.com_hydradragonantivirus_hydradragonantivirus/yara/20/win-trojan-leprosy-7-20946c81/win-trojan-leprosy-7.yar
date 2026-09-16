rule Win_Trojan_Leprosy_7
{
strings:
	$a0 = { ec568b7604eb04802c0a46803c00 }


condition:
	$a0
}