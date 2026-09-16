rule Win_Trojan_Grunt_6
{
strings:
	$a0 = { 1a3e8b9664028d9e2a0190b97e00f8311783c304fc83eb02e2f4c3e800005d81ed2201e8dbff }


condition:
	$a0
}