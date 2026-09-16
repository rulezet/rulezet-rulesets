rule Win_Trojan_AcDc_2
{
strings:
	$a0 = { 03e9a119032d0300a33103b440b90300ba3003cd21b801578b0e150380c91f8b161703cd21 }


condition:
	$a0
}