rule Win_Trojan_Davis_1
{
strings:
	$a0 = { 062e803ea7060074190e1f0e07be00008bfeb9a706fcacc0c8042e3206a706aae2f4eb95 }


condition:
	$a0
}