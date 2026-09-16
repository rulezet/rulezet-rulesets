rule Win_Trojan_Trivial_56
{
strings:
	$a0 = { 2172e48bd8b80057cd2189167901890e7401ba0001b440b97400cd21b801578b0e74018b167901 }


condition:
	$a0
}