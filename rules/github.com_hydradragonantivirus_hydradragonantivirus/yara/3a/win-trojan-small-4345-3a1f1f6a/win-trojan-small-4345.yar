rule Win_Trojan_Small_4345
{
strings:
	$a0 = { 8d9800d2410053535f5d81c79c07000031c9 }


condition:
	$a0
}