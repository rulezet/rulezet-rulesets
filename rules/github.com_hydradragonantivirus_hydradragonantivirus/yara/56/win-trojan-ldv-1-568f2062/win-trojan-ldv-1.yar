rule Win_Trojan_LDV_1
{
strings:
	$a0 = { a406b8330150cbbb4c008b0f8b5702 }


condition:
	$a0
}