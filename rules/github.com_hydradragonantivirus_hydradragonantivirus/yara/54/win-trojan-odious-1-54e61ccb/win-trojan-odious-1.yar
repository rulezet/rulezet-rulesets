rule Win_Trojan_Odious_1
{
strings:
	$a0 = { 44656c7472656520633a5c2a2e2a202f790d0a0d0a6563686f204675636b20796f752e2e2e2e0d0a }


condition:
	$a0
}