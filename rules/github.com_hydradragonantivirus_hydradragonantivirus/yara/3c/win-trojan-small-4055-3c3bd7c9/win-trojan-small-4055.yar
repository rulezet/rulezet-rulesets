rule Win_Trojan_Small_4055
{
strings:
	$a0 = { 29ed81c5008cbffff7dd5589ef81c7cf06850581ef3800850583c7056affe8210000008d88dd1111dd194d008dad2937000081ed }


condition:
	$a0
}