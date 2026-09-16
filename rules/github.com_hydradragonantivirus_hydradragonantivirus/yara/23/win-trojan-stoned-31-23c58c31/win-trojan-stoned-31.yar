rule Win_Trojan_Stoned_31
{
strings:
	$a0 = { 720833f6fcad3b07754133c9b404cd1a81fa07077401cbb80103bb0050b90100ba8000cd13b8 }


condition:
	$a0
}