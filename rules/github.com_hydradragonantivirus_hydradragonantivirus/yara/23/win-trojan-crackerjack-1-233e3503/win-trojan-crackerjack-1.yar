rule Win_Trojan_CrackerJack_1
{
strings:
	$a0 = { 1effb0c2b43dcd21a321038b1e2103b0 }


condition:
	$a0
}