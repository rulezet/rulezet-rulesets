rule Win_Trojan_Violator_3
{
strings:
	$a0 = { 8bf283c64290b90300bf0001f3a48bf2b430c606560401 }


condition:
	$a0
}