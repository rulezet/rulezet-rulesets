rule Win_Trojan_Kornik_2
{
strings:
	$a0 = { 208224b02f5018fe42d9ff0e51b02e0aff0acfff000435b0190d73ff08c0750ab0018a100a }


condition:
	$a0
}