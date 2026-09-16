rule Win_Trojan_PLO_1
{
strings:
	$a0 = { 5604b002b43dcd21a3bc20eb005d }


condition:
	$a0
}