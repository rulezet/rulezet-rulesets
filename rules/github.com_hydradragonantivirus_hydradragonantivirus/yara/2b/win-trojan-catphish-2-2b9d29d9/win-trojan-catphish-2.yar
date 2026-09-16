rule Win_Trojan_Catphish_2
{
strings:
	$a0 = { e800005d81ed0300e9a800bb210003ddb93f012e8a17d0ca2e881743e2f5e9 }


condition:
	$a0
}