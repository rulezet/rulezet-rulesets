rule Win_Trojan_Small_4236
{
strings:
	$a0 = { 8d9800d2410053535f5d81c79c070000be5e }


condition:
	$a0
}