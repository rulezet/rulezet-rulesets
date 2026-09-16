rule Win_Trojan_Small_4436
{
strings:
	$a0 = { 68????40000f6e04240f7ec0baeae7ff005250 }


condition:
	$a0
}