rule Win_Trojan_Open_7
{
strings:
	$a0 = { b90300ba7f04e8a4005872a026894515b440b92d069033d2e89200e8fe00eb8c837c1a007586 }


condition:
	$a0
}