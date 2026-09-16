rule Win_Trojan_Morphine_3
{
strings:
	$a0 = { eb92150d1d1d0c14fbd0139aa75fde322f116010de33979997741294e619d36617fadb1392e920d3 }


condition:
	$a0
}