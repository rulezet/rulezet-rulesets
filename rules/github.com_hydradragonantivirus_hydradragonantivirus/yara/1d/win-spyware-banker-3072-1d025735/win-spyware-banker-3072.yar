rule Win_Spyware_Banker_3072
{
strings:
	$a0 = { 1e174b7a7002d1a1cfd2c7beabe24fca235ec4a9c1b541a5395ce0791eabc4d6140f507d0f83b79f69bc4aea69959af4bba11a755567781f277448fa5b48 }


condition:
	$a0
}