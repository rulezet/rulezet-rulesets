rule Win_Trojan_Bancos_1797
{
strings:
	$a0 = { 92d4a97217421ccd21c9b27dd3ebe71989f14366bb5a86449496a6b551fc51e4cfcbef533034ecfdefd12577757dd08e836e3b90077c38547559fa4df4f147011bcaf16ef01f }


condition:
	$a0
}