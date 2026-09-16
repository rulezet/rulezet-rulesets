rule Win_Trojan__0026_0006_000_1
{
strings:
	$a0 = { b440cd21e80d00b91800baa702b440cd21e952ff32c0eb02b002b44233c933d2cd21c3bf02 }


condition:
	$a0
}