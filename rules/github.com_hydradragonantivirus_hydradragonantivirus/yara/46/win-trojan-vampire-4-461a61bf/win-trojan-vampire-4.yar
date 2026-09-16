rule Win_Trojan_Vampire_4
{
strings:
	$a0 = { 1aba7302cd21c3b409ba2902cd21b8004ccd21ba9102b8014333c9cd2172e8c38b1e7002b43fb90200ba6d02cd21a0 }


condition:
	$a0
}