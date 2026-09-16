rule Win_Trojan_Int10_1
{
strings:
	$a0 = { f14e388458007402e2f58a8c53005e5fc35351b9000226300f43e2fa595bc3 }


condition:
	$a0
}