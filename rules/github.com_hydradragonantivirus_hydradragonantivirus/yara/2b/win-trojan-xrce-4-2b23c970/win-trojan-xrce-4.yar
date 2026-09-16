rule Win_Trojan_Xrce_4
{
strings:
	$a0 = { 0e0e1f07ba????81c6????8bfeb92503ac32c602f2aae2f8 }


condition:
	$a0
}