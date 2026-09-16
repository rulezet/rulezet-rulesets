rule Win_Trojan_Fingers08_1
{
strings:
	$a0 = { ae26803d0075f84747478bd71e2e8c16 }


condition:
	$a0
}