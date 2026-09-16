rule Win_Trojan_Pray_1
{
strings:
	$a0 = { 0e1f33d2b94b02cd217318b800422e8b0e1b002e8b161900cd21b44033c9cd21eb27 }


condition:
	$a0
}