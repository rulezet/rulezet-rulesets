rule Win_Trojan_DNSChanger_165
{
strings:
	$a0 = { e80000000083c404434beb00e80000000083c404681b2141004149eb00c3 }


condition:
	$a0
}