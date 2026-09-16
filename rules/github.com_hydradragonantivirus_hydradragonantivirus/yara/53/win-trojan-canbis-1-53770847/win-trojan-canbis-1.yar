rule Win_Trojan_Canbis_1
{
strings:
	$a0 = { 6a008d442404506a1e6888d040006af5e862d2ffff50e894d2ffff6a008d442404506a0268683e40006af5e847d2ffff50e879d2ffff5ac3 }


condition:
	$a0
}