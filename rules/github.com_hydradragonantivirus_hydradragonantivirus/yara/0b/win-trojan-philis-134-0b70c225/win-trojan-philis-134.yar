rule Win_Trojan_Philis_134
{
strings:
	$a0 = { 538bd95b60564e5ee800000000500f00c0 }


condition:
	$a0
}