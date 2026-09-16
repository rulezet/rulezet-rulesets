rule Win_Trojan_MardiBros_1
{
strings:
	$a0 = { 8ec0be007c31ffb90014fcf3a406b8 }


condition:
	$a0
}