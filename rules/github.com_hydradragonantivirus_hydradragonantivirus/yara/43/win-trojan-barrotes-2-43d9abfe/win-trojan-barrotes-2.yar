rule Win_Trojan_Barrotes_2
{
strings:
	$a0 = { 017303e9fd00b903008d162401b440cd21e9ef000e1fe84b017303e9e500050200e85d018b }


condition:
	$a0
}