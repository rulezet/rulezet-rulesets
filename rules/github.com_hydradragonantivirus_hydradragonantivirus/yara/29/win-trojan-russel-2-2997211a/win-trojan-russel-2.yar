rule Win_Trojan_Russel_2
{
strings:
	$a0 = { c08ed88bc640fa8c0e0600a30400fb8bec9c8076ff018bfe81c74d009d2e8a04d9ee03d1d6e37e }


condition:
	$a0
}