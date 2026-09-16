rule Win_Trojan_Khizhnjak_27
{
strings:
	$a0 = { 01a04a032ea20101a04b032ea20201b99000bb00002e }


condition:
	$a0
}