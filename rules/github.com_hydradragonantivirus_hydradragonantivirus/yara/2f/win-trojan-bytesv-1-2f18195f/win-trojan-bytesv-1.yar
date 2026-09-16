rule Win_Trojan_ByteSV_1
{
strings:
	$a0 = { 014d5a743fb802429933c9cd21b4408bd5b97b0190cd21b800429933c9cd218b96d50183ea }


condition:
	$a0
}