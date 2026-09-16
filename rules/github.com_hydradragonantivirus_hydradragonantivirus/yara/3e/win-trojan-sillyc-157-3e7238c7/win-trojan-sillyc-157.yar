rule Win_Trojan_SillyC_157
{
strings:
	$a0 = { fd778489864d028d960401b90400b440cd218d960801b91b01b440cd21b800429933c9cd218b }


condition:
	$a0
}