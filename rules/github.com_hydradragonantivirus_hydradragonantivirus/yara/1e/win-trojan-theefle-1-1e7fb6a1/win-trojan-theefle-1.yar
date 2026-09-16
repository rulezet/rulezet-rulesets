rule Win_Trojan_Theefle_1
{
strings:
	$a0 = { a52d62c81bccfe9f2f59614242092ec17fb8efc8df5c1a6d61696c746f3a33300140807ad1fa7961686f6fb21e5cc483 }


condition:
	$a0
}