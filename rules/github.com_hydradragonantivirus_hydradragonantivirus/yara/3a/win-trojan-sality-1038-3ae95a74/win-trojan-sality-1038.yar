rule Win_Trojan_Sality_1038
{
strings:
	$a0 = { 02c55f478a440500300780e9015e4e0f85??ffffff }


condition:
	$a0
}