rule Win_Trojan_Trivial_217
{
strings:
	$a0 = { 4093ba0001b1279090cd21b44febe12a2e434f4d00 }


condition:
	$a0
}