rule Win_Trojan_Gen_86
{
strings:
	$a0 = { 2135cd21891e59018c065b018cc88ed8 }


condition:
	$a0
}