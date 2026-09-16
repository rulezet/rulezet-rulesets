rule Win_Trojan_Peed_233
{
strings:
	$a0 = { e8e0000000f7db29dff7db01de89c3eb745589e55389e38d61045089dc5b89d88b5d086b }


condition:
	$a0
}