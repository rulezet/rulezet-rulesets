rule Win_Trojan_Idiot_1
{
strings:
	$a0 = { fe066f022efe066f022efe066f022efe066f02eb193d5c2f5c3d204944494f542056554c54555245203d2f5c2f3d9c }


condition:
	$a0
}