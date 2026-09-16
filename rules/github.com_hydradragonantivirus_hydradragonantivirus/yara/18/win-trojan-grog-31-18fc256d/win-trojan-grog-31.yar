rule Win_Trojan_Grog_31
{
strings:
	$a0 = { e8ac007303eb7b90930e0e1f07b80057e89c005152 }


condition:
	$a0
}