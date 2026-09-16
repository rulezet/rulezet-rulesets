rule Win_Trojan_Trojan_82
{
strings:
	$a0 = { 8c062b00b82135cd21891e0f008c }


condition:
	$a0
}