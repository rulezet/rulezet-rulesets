rule Win_Trojan_Peed_189
{
strings:
	$a0 = { e82c00000068b0b9000068005ebfff5af7da595289e689d45889f405aa1a3301 }


condition:
	$a0
}