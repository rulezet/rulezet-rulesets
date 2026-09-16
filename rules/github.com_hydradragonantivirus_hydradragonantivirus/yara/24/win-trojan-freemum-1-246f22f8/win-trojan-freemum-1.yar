rule Win_Trojan_Freemum_1
{
strings:
	$a0 = { b440b9c800ba00f0cd2172deb8004233c933d2cd2172d3b440ba0001b9c800cd2172c7bf80 }


condition:
	$a0
}