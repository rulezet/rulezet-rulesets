rule Win_Trojan_Agent_35400
{
strings:
	$a0 = { 558bec83c4c4b8ec364000e8d0e0ffffb801000000e8 }

	$a1 = { 6b697778746d79756f74646a76636d6b }


condition:
	$a0 and $a1
}