rule Win_Adware_UCMore_4
{
strings:
	$a0 = { 9726170000007000000b0000004955434d4f52452e444c4cec5c7d541457967fdd5d4223 }


condition:
	$a0
}