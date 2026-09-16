rule Win_Spyware_1412_2
{
strings:
	$a0 = { 61696e2e70687000000000312e70687073000077616f }


condition:
	$a0
}