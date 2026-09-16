rule Win_Trojan_Ash_8
{
strings:
	$a0 = { 01b92a01b440cd21b800429933c9cd218b863d0240 }


condition:
	$a0
}