rule Win_Trojan_Ontario_4
{
strings:
	$a0 = { 8a84e801b9e801f6d02e300446e2f8 }


condition:
	$a0
}