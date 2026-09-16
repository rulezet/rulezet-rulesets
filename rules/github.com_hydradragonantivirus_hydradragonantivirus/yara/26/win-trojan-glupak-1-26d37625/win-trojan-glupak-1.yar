rule Win_Trojan_Glupak_1
{
strings:
	$a0 = { 89867d02b800429933c9cd21b90300b4408d967c02cd21e86800b98901b4408d960301cd21 }


condition:
	$a0
}