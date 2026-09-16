rule Win_Trojan_VLADAntipode_1
{
strings:
	$a0 = { e90000ff3601015a81c2030152be130003f2c704cd20c704c704e80300eb1190be2d0003f28bfeb9f502313c46e2fbc3 }


condition:
	$a0
}