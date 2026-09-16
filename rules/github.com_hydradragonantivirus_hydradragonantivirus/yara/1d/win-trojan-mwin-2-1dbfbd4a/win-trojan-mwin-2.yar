rule Win_Trojan_Mwin_2
{
strings:
	$a0 = { 4bbd8d1bce3feea9b8c6962f6a2a23b246d0bb254bf31726cd00ca884affe828fa24234690558249 }


condition:
	$a0
}