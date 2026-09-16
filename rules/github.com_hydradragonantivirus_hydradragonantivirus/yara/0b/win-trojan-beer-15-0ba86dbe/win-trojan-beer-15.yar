rule Win_Trojan_Beer_15
{
strings:
	$a0 = { 80fc3b7503e91eff3d003d740f3d023d740a80fc5674 }


condition:
	$a0
}