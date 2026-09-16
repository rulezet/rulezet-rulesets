rule Win_Trojan_Dikshev_38
{
strings:
	$a0 = { 9e00bf430157acaa3c0074093c2e75f6be3f01ebf15ab45bcd21720d93b440ba43009087d1cd21 }


condition:
	$a0
}