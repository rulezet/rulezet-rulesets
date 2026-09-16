rule Win_Trojan_Sality_1046
{
strings:
	$a0 = { 02c55f83c7018a440500555d3007 }


condition:
	$a0
}