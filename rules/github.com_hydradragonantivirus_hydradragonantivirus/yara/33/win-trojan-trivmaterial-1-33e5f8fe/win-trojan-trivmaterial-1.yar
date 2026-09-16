rule Win_Trojan_TrivMaterial_1
{
strings:
	$a0 = { 0180c44eba4a01cd21731cb42ccd2180fa4f7212b002b90100bb4e0199cd264273fbfec0ebf0c3fe064a0105023dba9e00cd2193b440ba0001b98000cd }


condition:
	$a0
}