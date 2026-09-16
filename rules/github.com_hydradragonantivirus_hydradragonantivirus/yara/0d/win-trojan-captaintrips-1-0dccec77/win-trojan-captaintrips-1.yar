rule Win_Trojan_CaptainTrips_1
{
strings:
	$a0 = { 2e8b8d1100cd218cc80410008ed0 }


condition:
	$a0
}