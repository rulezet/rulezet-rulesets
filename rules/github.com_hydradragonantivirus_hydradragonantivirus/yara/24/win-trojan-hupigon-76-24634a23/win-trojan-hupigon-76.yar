rule Win_Trojan_Hupigon_76
{
strings:
	$a0 = { 85c00f846302000068fcbc48006aff6a00e80ab3f7ff }


condition:
	$a0
}