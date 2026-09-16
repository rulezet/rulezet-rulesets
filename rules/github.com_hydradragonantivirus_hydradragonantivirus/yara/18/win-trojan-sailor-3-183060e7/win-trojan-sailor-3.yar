rule Win_Trojan_Sailor_3
{
strings:
	$a0 = { 0300b93b00f3a426c7062f00cd1053fec42bdbb90100cd135b1e07b80102b90e00b601cd13075b }


condition:
	$a0
}