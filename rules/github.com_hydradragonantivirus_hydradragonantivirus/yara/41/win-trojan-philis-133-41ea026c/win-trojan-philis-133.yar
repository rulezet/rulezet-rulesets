rule Win_Trojan_Philis_133
{
strings:
	$a0 = { 9bdbe26056f7de5ee800000000464e5a }


condition:
	$a0
}