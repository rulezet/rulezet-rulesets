rule Win_Trojan_Khizhnjak_32
{
strings:
	$a0 = { 02b900008b16f6028b1ef802b80042cd21723b8d161001b9f902908b1ef802b440cd217229 }


condition:
	$a0
}