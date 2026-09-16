rule Win_Trojan_Ming_2
{
strings:
	$a0 = { 03008d96ed02cd21b8024233c999cd21b9eb018d960301b440cd21b801575a59cd21b43ecd }


condition:
	$a0
}