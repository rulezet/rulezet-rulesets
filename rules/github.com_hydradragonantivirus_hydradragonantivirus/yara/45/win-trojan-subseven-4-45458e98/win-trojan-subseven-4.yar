rule Win_Trojan_SubSeven_4
{
strings:
	$a0 = { 6005edf043012adb975ea0300d3b1a1bb58b7926a4746961eb7f83283e6186514e4e4692f0a26bb6796bdb7e7b5ff08228c40207f0e73ebde9460cfabfbd44a2 }


condition:
	$a0
}