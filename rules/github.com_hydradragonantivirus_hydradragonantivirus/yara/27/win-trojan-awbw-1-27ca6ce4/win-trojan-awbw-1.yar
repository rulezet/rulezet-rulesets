rule Win_Trojan_AWBW_1
{
strings:
	$a0 = { 51005d5b8db6fdfffc86c487d151ac32c4aae2fa5903ca5ab440cd217213b800429933c9cd21 }


condition:
	$a0
}