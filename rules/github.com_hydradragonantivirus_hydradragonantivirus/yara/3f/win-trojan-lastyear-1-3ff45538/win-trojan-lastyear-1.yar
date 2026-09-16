rule Win_Trojan_Lastyear_1
{
strings:
	$a0 = { 1e1101b90500ba6001cd21b4408b1e1101b9e202ba1801cd21b801578b1e11018b0e5c018b }


condition:
	$a0
}