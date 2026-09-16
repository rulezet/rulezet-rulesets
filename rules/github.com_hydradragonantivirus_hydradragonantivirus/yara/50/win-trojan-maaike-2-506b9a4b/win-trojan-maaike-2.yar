rule Win_Trojan_Maaike_2
{
strings:
	$a0 = { be1501bf1501b97400ad33c3ab519be2fd59 }


condition:
	$a0
}