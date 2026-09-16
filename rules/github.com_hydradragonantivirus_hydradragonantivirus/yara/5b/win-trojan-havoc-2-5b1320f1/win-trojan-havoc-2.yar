rule Win_Trojan_Havoc_2
{
strings:
	$a0 = { 8ed88ed08ec0bc007cfbbe14044e8b04832c04b90600d3e02de0078ec0be007cbf007cb900 }


condition:
	$a0
}