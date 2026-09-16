rule Win_Trojan_Enemy1G_1
{
strings:
	$a0 = { b9af02482e300446e2f9c3 }


condition:
	$a0
}