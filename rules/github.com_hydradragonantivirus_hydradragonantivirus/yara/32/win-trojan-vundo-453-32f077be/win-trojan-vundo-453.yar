rule Win_Trojan_Vundo_453
{
strings:
	$a0 = { 807c2408010f859a0b000060be000002108dbe0010feff5789e58d9c2480c1ffff31c0 }


condition:
	$a0
}