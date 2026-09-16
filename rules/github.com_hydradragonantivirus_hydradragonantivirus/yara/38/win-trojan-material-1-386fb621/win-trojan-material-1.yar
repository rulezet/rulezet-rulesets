rule Win_Trojan_Material_1
{
strings:
	$a0 = { 02b90100bb4e0199cd264273fbfec0ebf0c3fe064a0105023dba9e00cd2193b440ba0001b98000 }


condition:
	$a0
}