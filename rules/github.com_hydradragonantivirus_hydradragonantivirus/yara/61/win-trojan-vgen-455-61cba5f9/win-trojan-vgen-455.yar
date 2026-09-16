rule Win_Trojan_VGEN_455
{
strings:
	$a0 = { 01a10101e8ee01803e030164721733d252b8020033dbb96400cd26585a83c26473eefaebfeb8414bcd218ed8582d }


condition:
	$a0
}