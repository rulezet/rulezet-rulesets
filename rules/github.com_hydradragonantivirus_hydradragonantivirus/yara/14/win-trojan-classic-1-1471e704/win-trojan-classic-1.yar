rule Win_Trojan_Classic_1
{
strings:
	$a0 = { 546865204e61726b6f746963204e6574776f726b203139393806003100 }


condition:
	$a0
}