rule Win_Trojan_AAEH_6
{
strings:
	$a0 = { 7a6b7064777066 }

	$a1 = { 69390b81cb66b00386223db6fc5edecd1d998851537384bfc1b345927731abf1bfd63bbb01c4fe65cde1d355699fdf8b }


condition:
	$a0 and $a1
}