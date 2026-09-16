rule Win_Trojan_Small_4251
{
strings:
	$a0 = { 8d98009c410053535f5d81c79c070000 }


condition:
	$a0
}