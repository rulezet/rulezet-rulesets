rule Win_Trojan_Shaker_1
{
strings:
	$a0 = { ff7504b8cdabcf80fc4b7523538bda803f00740343eb }


condition:
	$a0
}