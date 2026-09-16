rule Win_Trojan_Peed_315
{
strings:
	$a0 = { 4085c0754b51b95802000089d781c190010000e81400000059b8ffffffff }


condition:
	$a0
}