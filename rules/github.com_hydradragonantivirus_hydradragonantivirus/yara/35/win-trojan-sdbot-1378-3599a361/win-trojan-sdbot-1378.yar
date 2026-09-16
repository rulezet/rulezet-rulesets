rule Win_Trojan_SdBot_1378
{
strings:
	$a0 = { 61646572007365745f6d65007365745f6d65007364626f74207630 }


condition:
	$a0
}