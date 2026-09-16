rule Win_Trojan_Guide_1
{
strings:
	$a0 = { 075d5583ed07be070003f58bfeb905053e8aa60c05fcac32c4aae2fac3 }


condition:
	$a0
}