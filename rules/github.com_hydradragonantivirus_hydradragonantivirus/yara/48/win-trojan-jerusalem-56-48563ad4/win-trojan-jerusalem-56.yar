rule Win_Trojan_Jerusalem_56
{
strings:
	$a0 = { b9eb05f61d47e2fbc3 }

	$a1 = { bf0a00bec6008cda8cc839d07506bf0a01be96011e0e1fe8ddff1f56c3 }


condition:
	$a0 and $a1
}