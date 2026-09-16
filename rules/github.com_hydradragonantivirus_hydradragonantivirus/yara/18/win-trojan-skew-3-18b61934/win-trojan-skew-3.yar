rule Win_Trojan_Skew_3
{
strings:
	$a0 = { 51525653558bec80fc3d75228bfab93f0047803d }


condition:
	$a0
}