rule Win_Trojan_Mini_75
{
strings:
	$a0 = { 5a01905459cd21803e5a01927414055a00905033c9f7e1b442cd2159b4405a52cd21b44feb }


condition:
	$a0
}