rule Win_Trojan_Faod_1
{
strings:
	$a0 = { cd2180fc0d750f8cd80510002e010693052eff2e91052bf6bf0001b99905fc2ef3a48cd805100050682e00cbb44a }


condition:
	$a0
}