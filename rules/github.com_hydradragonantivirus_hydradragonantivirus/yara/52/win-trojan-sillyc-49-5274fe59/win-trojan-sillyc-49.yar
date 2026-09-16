rule Win_Trojan_SillyC_49
{
strings:
	$a0 = { 030089869101b440b99d008d960001cd21b800429933c9cd21b4408d969001b90300cd21b80157 }


condition:
	$a0
}