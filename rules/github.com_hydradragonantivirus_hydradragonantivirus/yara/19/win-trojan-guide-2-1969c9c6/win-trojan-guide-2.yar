rule Win_Trojan_Guide_2
{
strings:
	$a0 = { 070003f58bfeb908053e8aa60f05fcac32c4aae2fac3 }


condition:
	$a0
}