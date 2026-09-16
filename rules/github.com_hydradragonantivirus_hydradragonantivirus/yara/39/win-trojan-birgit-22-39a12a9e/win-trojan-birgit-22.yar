rule Win_Trojan_Birgit_22
{
strings:
	$a0 = { e2fdba1602ffd2c353bafe01ffd25bb440b91601ba0001cd2153bafe01ffd25bc3 }


condition:
	$a0
}