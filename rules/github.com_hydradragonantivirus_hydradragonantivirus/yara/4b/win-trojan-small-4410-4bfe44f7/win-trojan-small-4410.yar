rule Win_Trojan_Small_4410
{
strings:
	$a0 = { e804000000272e4200588b00505068 }


condition:
	$a0
}