rule Win_Trojan_Winwebsec_1
{
strings:
	$a0 = { 33c981c100b006015133c981c99830000166832100ff31588bd06a3c01042459 }


condition:
	$a0
}