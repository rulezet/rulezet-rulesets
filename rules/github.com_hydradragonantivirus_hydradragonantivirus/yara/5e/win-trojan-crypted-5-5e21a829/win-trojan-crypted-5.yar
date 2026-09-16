rule Win_Trojan_Crypted_5
{
strings:
	$a0 = { b818000000648b1883c330c3403e0fb600c1e00??3c0??36010424c3[0-255]6160e8????ffff8bc33e8b0040e8????ffff }


condition:
	$a0
}