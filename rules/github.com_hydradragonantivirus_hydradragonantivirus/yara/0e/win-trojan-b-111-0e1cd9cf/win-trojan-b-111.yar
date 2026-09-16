rule Win_Trojan_B_111
{
strings:
	$a0 = { db8ed3bc007c8ec4b80802b90150ba0000cd1372000668c300cb }


condition:
	$a0
}