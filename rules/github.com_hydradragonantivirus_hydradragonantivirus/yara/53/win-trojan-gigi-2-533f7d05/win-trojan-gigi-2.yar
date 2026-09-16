rule Win_Trojan_Gigi_2
{
strings:
	$a0 = { eb018c2ec7060601c300bb1700b90400be000033fff3a4415359b90100ba78094a0bc1fec4e2f6b40332ffcd }


condition:
	$a0
}