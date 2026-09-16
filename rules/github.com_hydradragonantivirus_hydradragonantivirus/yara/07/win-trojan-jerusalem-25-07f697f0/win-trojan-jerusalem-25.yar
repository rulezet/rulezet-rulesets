rule Win_Trojan_Jerusalem_25
{
strings:
	$a0 = { 26c7060e0090cb580510008ec00e1fb9 }


condition:
	$a0
}