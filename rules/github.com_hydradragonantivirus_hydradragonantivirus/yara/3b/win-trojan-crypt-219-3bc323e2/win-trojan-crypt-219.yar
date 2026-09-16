rule Win_Trojan_Crypt_219
{
strings:
	$a0 = { 807c2408010f859a0b000060be004002108dbe00d0fdff5789e58d9c2480c1ffff31c05039dc75 }


condition:
	$a0
}