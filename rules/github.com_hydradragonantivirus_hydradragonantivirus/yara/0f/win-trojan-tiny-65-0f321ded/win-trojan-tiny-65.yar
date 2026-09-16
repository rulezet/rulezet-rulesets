rule Win_Trojan_Tiny_65
{
strings:
	$a0 = { 5e81ee0b018bacd10181c503018d94d3 }


condition:
	$a0
}