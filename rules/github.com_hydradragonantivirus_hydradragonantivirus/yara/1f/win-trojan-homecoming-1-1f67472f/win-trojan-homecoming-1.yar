rule Win_Trojan_Homecoming_1
{
strings:
	$a0 = { cd21b8024233c999cd218d966205b91200b440cd21e8d8018d961200b92005b440cd21e8cf01 }


condition:
	$a0
}