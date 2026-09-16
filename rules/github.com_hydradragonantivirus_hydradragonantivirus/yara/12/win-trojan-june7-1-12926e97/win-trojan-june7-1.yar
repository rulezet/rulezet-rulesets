rule Win_Trojan_June7_1
{
strings:
	$a0 = { 018ccb81c33f005350cb }


condition:
	$a0
}