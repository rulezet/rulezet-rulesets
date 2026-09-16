rule Win_Trojan_Vampiro_1
{
strings:
	$a0 = { b901008d96b604cd2168004058b902008d96ca03cd2168004058b904008d96b104cd2168 }


condition:
	$a0
}