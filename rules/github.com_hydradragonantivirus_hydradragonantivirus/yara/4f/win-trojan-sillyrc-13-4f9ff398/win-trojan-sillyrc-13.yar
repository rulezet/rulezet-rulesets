rule Win_Trojan_SillyRC_13
{
strings:
	$a0 = { 058c4507c64504eaba6300b425cd215ebf0001570e1f }


condition:
	$a0
}