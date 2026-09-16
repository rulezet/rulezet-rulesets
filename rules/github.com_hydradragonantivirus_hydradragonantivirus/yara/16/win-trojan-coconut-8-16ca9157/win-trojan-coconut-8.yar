rule Win_Trojan_Coconut_8
{
strings:
	$a0 = { 01b968088bfeacf6d0aae2fac3e803fac686ed0901 }


condition:
	$a0
}