rule Win_Trojan_Carol_1
{
strings:
	$a0 = { 7c005589e5bfb8050e57bf58001e57b8ff00509aa2087c00bf58001e57e817fabf382f1e57bf58001e5731c050 }


condition:
	$a0
}