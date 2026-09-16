rule Win_Trojan_Carol_2
{
strings:
	$a0 = { cd21c3bf56001e07b9882c2bcfd1e933c0fcf3abc300000000000000000000000000054361726f6c }


condition:
	$a0
}