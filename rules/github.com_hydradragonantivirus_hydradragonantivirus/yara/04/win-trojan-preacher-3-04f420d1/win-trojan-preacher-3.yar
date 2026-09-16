rule Win_Trojan_Preacher_3
{
strings:
	$a0 = { b44a0e07cd21b43cb90200ba0b01cd218bd87304b001eb6cb4402e8b0efc02ba0c03cd21b43ecd218cc82ea3f2 }


condition:
	$a0
}