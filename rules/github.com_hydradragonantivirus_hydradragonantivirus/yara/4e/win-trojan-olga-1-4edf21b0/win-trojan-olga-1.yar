rule Win_Trojan_Olga_1
{
strings:
	$a0 = { 8ccd8b1e020083eb218ec3061e0e1f012ead00be1d00ba8000b9010033dbb80102cd1326803fb1742051b104b80103 }


condition:
	$a0
}