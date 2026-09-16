rule Win_Spyware_Banker_2447
{
strings:
	$a0 = { 2b680f15dd8d0e9c1490948e3632118161f2f2401931a99d3f6a25f0cd9cc56fc624e419b2f09cf6acfcf032f540bbe10ef635f11e7aded66673ceb12d733d712b8739d5ec6a72dc8e7c }


condition:
	$a0
}