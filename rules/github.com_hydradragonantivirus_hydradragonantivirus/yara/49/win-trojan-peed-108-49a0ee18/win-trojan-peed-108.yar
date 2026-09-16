rule Win_Trojan_Peed_108
{
strings:
	$a0 = { 6a00e9ae000000bf00??a8e1bbf9ffffff01c789f89683c30783c40283c402b877150000e81a000000eb5555 }


condition:
	$a0
}