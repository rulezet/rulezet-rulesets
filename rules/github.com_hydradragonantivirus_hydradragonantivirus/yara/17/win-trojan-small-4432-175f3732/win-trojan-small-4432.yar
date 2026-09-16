rule Win_Trojan_Small_4432
{
strings:
	$a0 = { e8040000005e2e4200588b00505068ec }


condition:
	$a0
}