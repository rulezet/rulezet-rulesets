rule Win_Trojan_VLAD_5
{
strings:
	$a0 = { 015a81c2030152be130003f2c704cd20c704c704e80200eb10be2c0003f28bfeb9b502313c46e2fbc3 }


condition:
	$a0
}