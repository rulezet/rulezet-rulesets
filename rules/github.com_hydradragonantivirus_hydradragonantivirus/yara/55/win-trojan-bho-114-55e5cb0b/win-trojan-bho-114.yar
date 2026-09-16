rule Win_Trojan_BHO_114
{
strings:
	$a0 = { 525651505383e600570f8499feffff1d }

	$a1 = { 654150492e666e65 }

	$a2 = { 3d2fd1621a2bc1631a2bc16e1a2bc1631d2b41621a2bc1f23c2f }


condition:
	$a0 and $a1 and $a2
}