rule Win_Trojan_Sality_1042
{
strings:
	$a0 = { 83c7018a440500300789d2fec95e4e0f84??000000 }


condition:
	$a0
}