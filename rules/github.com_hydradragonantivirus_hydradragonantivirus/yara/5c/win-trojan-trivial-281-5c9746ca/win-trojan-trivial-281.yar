rule Win_Trojan_Trivial_281
{
strings:
	$a0 = { 4eba2401cd21720bb8013d99b29ecd21b74087c399b12dfec6cd21b43ecd21b44febde2a2e436f }


condition:
	$a0
}