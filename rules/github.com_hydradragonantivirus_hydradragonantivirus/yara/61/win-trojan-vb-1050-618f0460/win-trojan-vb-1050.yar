rule Win_Trojan_VB_1050
{
strings:
	$a0 = { 5c00630073006d00670072002e0064006c006c }


condition:
	$a0
}