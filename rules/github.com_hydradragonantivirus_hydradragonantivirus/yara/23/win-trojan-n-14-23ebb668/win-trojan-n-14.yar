rule Win_Trojan_N_14
{
strings:
	$a0 = { 8b9621038db60900b9650131144646e2fac3e800005d81 }


condition:
	$a0
}