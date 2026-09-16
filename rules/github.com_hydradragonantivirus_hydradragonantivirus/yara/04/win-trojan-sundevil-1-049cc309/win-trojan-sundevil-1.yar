rule Win_Trojan_Sundevil_1
{
strings:
	$a0 = { e80100??5d81ed0300b42acd2181fa08057402eb1cb419cd2133dbb9010033d2cd26 }


condition:
	$a0
}