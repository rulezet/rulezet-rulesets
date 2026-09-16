rule Win_Trojan_Virogen_8
{
strings:
	$a0 = { 7217d7913b11d2993311d2992f11d2993711ea3d9336deed576268a3579ac8ce5bda7f249e999ead }


condition:
	$a0
}