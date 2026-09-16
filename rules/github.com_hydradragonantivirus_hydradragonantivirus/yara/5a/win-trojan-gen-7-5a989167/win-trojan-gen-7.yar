rule Win_Trojan_Gen_7
{
strings:
	$a0 = { cd21b448bb9600cd212ea3cb01b82425bacd01cd21b42acd2180fa01750ab409ba5c01cd21 }


condition:
	$a0
}