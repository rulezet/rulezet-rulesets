rule Win_Trojan_Philis_91
{
strings:
	$a0 = { 81c6d91bd02d5481eed91bd02d89342468947e800d83c4048b7424fc013424 }


condition:
	$a0
}