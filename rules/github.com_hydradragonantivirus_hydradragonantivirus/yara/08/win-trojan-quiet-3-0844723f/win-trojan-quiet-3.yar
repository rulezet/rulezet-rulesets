rule Win_Trojan_Quiet_3
{
strings:
	$a0 = { 8ec0bbffff4326803f0075f926807f010075f283c3 }


condition:
	$a0
}