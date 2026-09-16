rule Win_Trojan_SillyC_27
{
strings:
	$a0 = { 213d00f07721fec4a304018bd6b97600b440cd2133c933d2b80042cd21ba0001b97600b440cd21b4 }


condition:
	$a0
}