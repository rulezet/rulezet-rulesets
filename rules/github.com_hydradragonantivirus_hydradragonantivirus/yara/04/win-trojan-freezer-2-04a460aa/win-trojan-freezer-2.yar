rule Win_Trojan_Freezer_2
{
strings:
	$a0 = { 565181c63e00b996032e3004fec046e2f8595e58c39c9a }


condition:
	$a0
}