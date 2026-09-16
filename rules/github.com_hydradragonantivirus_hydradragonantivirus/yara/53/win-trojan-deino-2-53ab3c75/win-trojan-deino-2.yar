rule Win_Trojan_Deino_2
{
strings:
	$a0 = { f3a43e8086a303015b53b440b902008d96a303cd215b53b440b904008d96ac03cd215b53 }


condition:
	$a0
}