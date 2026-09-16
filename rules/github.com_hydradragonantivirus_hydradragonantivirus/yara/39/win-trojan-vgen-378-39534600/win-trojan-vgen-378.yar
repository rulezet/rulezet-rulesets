rule Win_Trojan_VGEN_378
{
strings:
	$a0 = { e800005dbf00018db64a00a5a5b41a8d967f02cd218d96440033c9b44ecd217303e9af008d969d02b8023dcd2193b43f }


condition:
	$a0
}