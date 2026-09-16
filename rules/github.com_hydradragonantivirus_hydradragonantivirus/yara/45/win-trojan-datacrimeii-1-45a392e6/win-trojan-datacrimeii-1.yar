rule Win_Trojan_DataCrimeII_1
{
strings:
	$a0 = { 8a072ec6052232c2d0ca2e8807432e }


condition:
	$a0
}