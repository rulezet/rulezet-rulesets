rule Win_Trojan_SillyC_31
{
strings:
	$a0 = { d275232d030089847e00b4408bd6b97e00cd21b800429933c9cd21b440b903008d947d00cd }


condition:
	$a0
}