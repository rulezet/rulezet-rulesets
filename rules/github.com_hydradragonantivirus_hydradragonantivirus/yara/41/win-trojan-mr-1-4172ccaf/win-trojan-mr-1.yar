rule Win_Trojan_Mr_1
{
strings:
	$a0 = { 4b75392e8c1638002e89263600bca1052e8e163a00 }


condition:
	$a0
}