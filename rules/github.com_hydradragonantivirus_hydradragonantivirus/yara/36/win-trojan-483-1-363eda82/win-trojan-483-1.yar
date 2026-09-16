rule Win_Trojan_483_1
{
strings:
	$a0 = { e82e00b440b91800bae303cd50b002 }


condition:
	$a0
}