rule Win_Trojan_Srp_5
{
strings:
	$a0 = { ff7505b8ffffeb13b8020050b8340950b8010050e829038be5eb005dc3558becb4098b5604cd }


condition:
	$a0
}