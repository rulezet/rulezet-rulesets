rule Win_Trojan_Plasmahttp_1
{
strings:
	$a0 = { 0e500072006f0063004d006f006e00000000000a4d0069006e00650072009301 }


condition:
	$a0
}