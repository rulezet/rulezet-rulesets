rule Win_Trojan_V_67
{
strings:
	$a0 = { 5d81ed0701b80035cd218c863003899e3203b800258d963b01cd2133dbf7f38d9e350153c7 }


condition:
	$a0
}