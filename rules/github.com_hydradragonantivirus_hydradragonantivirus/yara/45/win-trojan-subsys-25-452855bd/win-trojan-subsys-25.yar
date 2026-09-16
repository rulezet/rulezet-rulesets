rule Win_Trojan_Subsys_25
{
strings:
	$a0 = { 5a7e00e91a35924d603c2e4699400aadef2f95483d4c7593f9df34ac55dc4fa415940bc6497b4ffdb2bb9b0276d18f1a }


condition:
	$a0
}