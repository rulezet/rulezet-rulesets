rule Win_Trojan_OneHalf_10
{
strings:
	$a0 = { 5515eeb0150ea1a591772e2cf591d1430226b3c2d0d20118fb7e91e3701aa532f117b74545953e1bc718be2f7fbd3bdb }


condition:
	$a0
}