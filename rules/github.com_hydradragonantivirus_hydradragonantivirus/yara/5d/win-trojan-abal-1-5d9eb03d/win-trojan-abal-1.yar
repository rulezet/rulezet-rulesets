rule Win_Trojan_Abal_1
{
strings:
	$a0 = { ba0000b440cd21e87000b43ecd21c3be0801b200b447cd21c30e1fba4901b8023dcd21505bc3 }


condition:
	$a0
}