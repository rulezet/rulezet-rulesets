rule Win_Trojan_Jerusalem_11
{
strings:
	$a0 = { cd2180fcf1741480fca1750fbe9603bf0001b4c12e8b0e9501cd218c069d018c06a9018c06ad }


condition:
	$a0
}