rule Win_Trojan_HG_1
{
strings:
	$a0 = { 0980c43933c933d2cd2db40980c437b91800bac001cd2db801578b0ec0008b16c200cd2db43e }


condition:
	$a0
}