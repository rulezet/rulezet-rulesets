rule Win_Trojan_Xuxa_1
{
strings:
	$a0 = { be10013030741b8db63a018dbe3a01b9d4038a04c0c00526880546474975f3eb01 }


condition:
	$a0
}