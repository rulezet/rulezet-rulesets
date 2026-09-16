rule Win_Trojan_Zbot_1246
{
strings:
	$a0 = { 558bec81c4c8feffff60f7d933f333f6e82cfbffff8d1db03946a881e62c74dcb433c881d7e3395a32ff15 }


condition:
	$a0
}