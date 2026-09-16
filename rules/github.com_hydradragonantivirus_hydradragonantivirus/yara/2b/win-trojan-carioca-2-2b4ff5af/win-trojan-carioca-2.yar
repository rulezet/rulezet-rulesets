rule Win_Trojan_Carioca_2
{
strings:
	$a0 = { b82725ba5c01cd21b82035cd212e }


condition:
	$a0
}