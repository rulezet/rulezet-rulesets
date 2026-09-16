rule Win_Trojan_One_Half_1
{
strings:
	$a0 = { 1556c272f9d4ff88e08ed889c380cb06ff77feff37 }


condition:
	$a0
}