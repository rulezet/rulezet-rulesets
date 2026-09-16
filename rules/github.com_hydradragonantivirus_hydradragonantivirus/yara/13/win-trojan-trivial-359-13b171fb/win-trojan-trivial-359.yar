rule Win_Trojan_Trivial_359
{
strings:
	$a0 = { b02aaab000aacd217301c3a13b01ba9e00cd21938a263d01b94e00ba0001cd218a263e01cd }


condition:
	$a0
}