rule Win_Trojan_Dikshev_37
{
strings:
	$a0 = { 0157acaa3c0074093c2e75f6be3e01ebf15ab45bcd21720c93b440ba420087d1cd2187d1b44f }


condition:
	$a0
}