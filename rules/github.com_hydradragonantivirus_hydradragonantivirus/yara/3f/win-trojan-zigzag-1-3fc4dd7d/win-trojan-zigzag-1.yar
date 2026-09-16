rule Win_Trojan_ZigZag_1
{
strings:
	$a0 = { 20b8023dba9e00cd2193b43fb90200ba6d01cd21813e }


condition:
	$a0
}