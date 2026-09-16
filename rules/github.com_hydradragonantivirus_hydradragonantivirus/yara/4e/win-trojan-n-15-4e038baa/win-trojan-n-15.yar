rule Win_Trojan_N_15
{
strings:
	$a0 = { 961e038db60900b9640131144646e2fac3e800005d81 }


condition:
	$a0
}