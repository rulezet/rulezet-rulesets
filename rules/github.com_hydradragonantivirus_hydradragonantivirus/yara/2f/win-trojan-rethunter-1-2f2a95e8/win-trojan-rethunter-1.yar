rule Win_Trojan_RetHunter_1
{
strings:
	$a0 = { 2193e82600b43fb901008d562490cd21b0013cc3750de81200b440b950008d56fdcd21b43ecd21 }


condition:
	$a0
}