rule Win_Trojan_Jerusalem_12
{
strings:
	$a0 = { cd2180fcf1741480fca1750fbf0001be9603b4c12e8b0e9501cd218c069d018c06a9018c06ad018c06b101bb8000 }


condition:
	$a0
}