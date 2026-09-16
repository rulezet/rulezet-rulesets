rule Win_Trojan_AntiAVP_2
{
strings:
	$a0 = { 02429933c9cd21b4408bd5b9bf03cd21b800429933c9cd }


condition:
	$a0
}