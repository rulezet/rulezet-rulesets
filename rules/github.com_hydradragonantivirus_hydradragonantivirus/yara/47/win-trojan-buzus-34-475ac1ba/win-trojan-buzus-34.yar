rule Win_Trojan_Buzus_34
{
strings:
	$a0 = { 5589e583ec146a02ff1504824100e8fdfeffff8db6000000008dbc27000000005589e583ec146a01ff150482 }


condition:
	$a0
}