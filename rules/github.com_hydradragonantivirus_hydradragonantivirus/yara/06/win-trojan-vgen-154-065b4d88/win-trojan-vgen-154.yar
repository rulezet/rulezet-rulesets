rule Win_Trojan_VGEN_154
{
strings:
	$a0 = { 210ae4742933c05007be0001010102b9c300f3a5061fbf8603be8400bb4d02e82001018e03be5800bb5703e814 }


condition:
	$a0
}