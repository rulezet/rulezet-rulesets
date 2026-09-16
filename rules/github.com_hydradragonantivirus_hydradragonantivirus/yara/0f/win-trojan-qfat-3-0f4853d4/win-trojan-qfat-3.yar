rule Win_Trojan_QFat_3
{
strings:
	$a0 = { b707b500b100b619b250cd10b402b700ba0000cd1007b80200b9b80bfa99cd26fbf4b8004ccd21 }


condition:
	$a0
}