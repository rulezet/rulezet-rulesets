rule Win_Trojan_VP_4
{
strings:
	$a0 = { b97d03cd218cc28edab457b0018b1e20038b0edc028b16de02cd21 }


condition:
	$a0
}