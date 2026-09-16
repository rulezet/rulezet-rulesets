rule Win_Trojan_Marked_1
{
strings:
	$a0 = { 1fb8004233c999cd21b96201b440ba0001cd219933c9b80157cd21b43ecd211f5a595b589d }


condition:
	$a0
}