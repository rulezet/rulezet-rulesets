rule Win_Trojan_Mini_82
{
strings:
	$a0 = { cd2193061fb43f575a5459cd2150b800429933c9cd2159890e1d0181c16200b440565acd210e1f }


condition:
	$a0
}