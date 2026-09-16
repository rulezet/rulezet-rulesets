rule Win_Trojan_Buzus_41
{
strings:
	$a0 = { 57e85aebffffe855ffffff33ff33c933c05fc210009090909090909090909090 }


condition:
	$a0
}