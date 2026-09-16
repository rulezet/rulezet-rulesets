rule Win_Trojan_Bzz_1
{
strings:
	$a0 = { e800008bf48304088b34c387f581ed0e018db62b012e8a245680f4908bfeb9f800ac32c4aae2fac3 }


condition:
	$a0
}