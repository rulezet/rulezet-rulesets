rule Win_Trojan_Banload_2085
{
strings:
	$a0 = { 558becb8290a9866bbdbbe5c4e50e800000000582da81a0000b96d }

	$a1 = { 7655227378572373755522ff }


condition:
	$a0 and $a1
}