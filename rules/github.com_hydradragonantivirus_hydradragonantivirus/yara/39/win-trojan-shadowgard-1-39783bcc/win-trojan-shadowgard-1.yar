rule Win_Trojan_Shadowgard_1
{
strings:
	$a0 = { 23015589e531c09a7c022301e84efee874fabf00251e57e8b1f6803e4e24017506b00150e8cdefe80cfbe8dbf8 }


condition:
	$a0
}