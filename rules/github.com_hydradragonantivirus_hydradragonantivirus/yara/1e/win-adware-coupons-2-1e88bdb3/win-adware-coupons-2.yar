rule Win_Adware_Coupons_2
{
strings:
	$a0 = { 6367692d62696e2f25732e6578650000427269636b73436f6465 }

	$a1 = { 636f75706f6e4944 }


condition:
	$a0 and $a1
}