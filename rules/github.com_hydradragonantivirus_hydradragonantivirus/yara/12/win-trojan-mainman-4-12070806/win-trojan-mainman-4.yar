rule Win_Trojan_Mainman_4
{
strings:
	$a0 = { cd215eba3b0203d6b44e33c9cd21b80143ba9e00 }


condition:
	$a0
}