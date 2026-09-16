rule Win_Trojan_VCS_1
{
strings:
	$a0 = { e2fac35e81ee030156e8e3ff }


condition:
	$a0
}