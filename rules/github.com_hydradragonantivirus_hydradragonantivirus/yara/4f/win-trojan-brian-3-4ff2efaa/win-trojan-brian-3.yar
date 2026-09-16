rule Win_Trojan_Brian_3
{
strings:
	$a0 = { 6e005589e5bfe5040e57bf58001e57b8ff00509a9f066e00b42ccd2188365600bf58001e57e8b4fa803e56001e }


condition:
	$a0
}