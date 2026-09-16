rule Win_Trojan_VLAD_3
{
strings:
	$a0 = { 01015a81eafdfe52be130003f2c704cd20c704c704e80300eb1590be310003f28bfe81ef4001b90e04313c46e2fb }


condition:
	$a0
}