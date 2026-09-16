rule Win_Trojan_Darkmoon_25
{
strings:
	$a0 = { 65205365727665722e2e2e00ffffffff0a000000254461726b4d6f6f6e250000ffffffff01 }


condition:
	$a0
}