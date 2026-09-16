rule Win_Trojan_N_21
{
strings:
	$a0 = { ff8edfb832588706d2053d3258743cb44a8d5dffcd2183eb2ab44acd21722c03c38ec026c74501 }


condition:
	$a0
}