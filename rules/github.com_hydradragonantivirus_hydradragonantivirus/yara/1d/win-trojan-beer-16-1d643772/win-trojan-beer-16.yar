rule Win_Trojan_Beer_16
{
strings:
	$a0 = { 3b7503e917ff3d003d740f3d023d740a80fc5674 }


condition:
	$a0
}