rule Win_Trojan_Major_1
{
strings:
	$a0 = { 2bc603f08bca8bfb81c73000880d4381fb3b0675db }


condition:
	$a0
}