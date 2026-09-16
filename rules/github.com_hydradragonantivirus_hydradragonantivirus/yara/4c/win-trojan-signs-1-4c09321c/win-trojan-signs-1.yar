rule Win_Trojan_Signs_1
{
strings:
	$a0 = { 56559c80fc4b75e48bf2fcac22c07402ebf9817cfc }


condition:
	$a0
}