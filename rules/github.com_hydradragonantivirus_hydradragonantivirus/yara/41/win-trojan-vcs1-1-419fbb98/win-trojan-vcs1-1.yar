rule Win_Trojan_VCS1_1
{
strings:
	$a0 = { 89feac32c4aae2fac35e81ee030156e8 }


condition:
	$a0
}