rule Win_Trojan_Touch_2
{
strings:
	$a0 = { b054ef16b02bec1d0466062fc5d736d4b0562a9f1a }


condition:
	$a0
}