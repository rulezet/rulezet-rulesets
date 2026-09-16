rule Win_Trojan_Gotcha_14
{
strings:
	$a0 = { 3ddada742e5251535056571e0680fc3e7504b445eb073d }


condition:
	$a0
}