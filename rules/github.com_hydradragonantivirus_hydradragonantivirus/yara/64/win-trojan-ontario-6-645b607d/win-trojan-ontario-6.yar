rule Win_Trojan_Ontario_6
{
strings:
	$a0 = { e801b9e801f6d02e300446e2f8c3 }


condition:
	$a0
}