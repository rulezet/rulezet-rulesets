rule Win_Trojan_Pandaflu_1
{
strings:
	$a0 = { c9b80042cd21ba0001b9aa05b440cd21 }


condition:
	$a0
}