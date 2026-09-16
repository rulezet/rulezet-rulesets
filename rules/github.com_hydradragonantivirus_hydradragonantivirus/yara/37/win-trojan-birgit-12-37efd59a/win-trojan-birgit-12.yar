rule Win_Trojan_Birgit_12
{
strings:
	$a0 = { be5903f3a43e80865903015b53b440b902008d965903cd215b53b440b904008d966203cd215b53 }


condition:
	$a0
}