rule Win_Trojan_Trivial_102
{
strings:
	$a0 = { 2a0032c9b44e8bd1cd21ba9e00b43cb740cd219387ca }


condition:
	$a0
}