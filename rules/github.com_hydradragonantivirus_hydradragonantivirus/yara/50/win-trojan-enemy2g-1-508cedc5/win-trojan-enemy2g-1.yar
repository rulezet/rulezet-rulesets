rule Win_Trojan_Enemy2G_1
{
strings:
	$a0 = { b9af02402e300446e2f9c3 }


condition:
	$a0
}