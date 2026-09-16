rule Win_Trojan_Satana_2
{
strings:
	$a0 = { ee0350535152571e0656b8f1edcd213dffff74378cc0488ec0bb030026832f2b904b8b072d2b0089078ec033fffc }


condition:
	$a0
}