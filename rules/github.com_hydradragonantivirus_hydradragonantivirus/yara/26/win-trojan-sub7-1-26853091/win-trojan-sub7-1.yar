rule Win_Trojan_Sub7_1
{
strings:
	$a0 = { 4152455c537562536576656e5c0000ffffffff01 }


condition:
	$a0
}