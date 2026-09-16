rule Win_Trojan_Parasite_9
{
strings:
	$a0 = { 1101b91300b43fcd2189d6bffe00f3a67426b80057cd215152b440b9110133d2cd21b80042 }


condition:
	$a0
}