rule Win_Trojan_Delf_1637
{
strings:
	$a0 = { 558bec83c4ec33c08945ecb804314000e8eff0ffff33c05568ba31400064ff306489208d45ece865f5ffff8b45ecbad0314000e8acecffff750733c0e8d7e9ffff }


condition:
	$a0
}