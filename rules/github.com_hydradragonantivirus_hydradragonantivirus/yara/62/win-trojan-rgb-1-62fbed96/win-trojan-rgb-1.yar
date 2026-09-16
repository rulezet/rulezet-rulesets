rule Win_Trojan_RGB_1
{
strings:
	$a0 = { 1101b89090a31701bf1901b907029035e947e2facd20 }


condition:
	$a0
}