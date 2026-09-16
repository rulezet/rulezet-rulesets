rule Win_Trojan_LSD_1
{
strings:
	$a0 = { b2008db6dd06cd217500bada06b43bcd217500ba1d0755b44ecd217228b42fcd218bf3b8014333c98d541ecd21b8023dcd2193b440b94006ba0001cd21b4 }


condition:
	$a0
}