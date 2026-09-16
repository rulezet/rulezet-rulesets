rule Win_Trojan_Small_4542
{
strings:
	$a0 = { 56648b403085c0780c8b400c8b701cad8b4008eb098b40348d407c8b403c5ec3 }

	$a1 = { 48746148744f4874 }


condition:
	$a0 and $a1
}