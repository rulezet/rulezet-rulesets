rule Win_Trojan_Search_5
{
strings:
	$a0 = { a8e90163e2f7baea0103d6b44e33c9cd21b905008bd980 }


condition:
	$a0
}