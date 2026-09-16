rule Win_Trojan_Open_6
{
strings:
	$a0 = { 040326c745150000b440b90300ba7e04e8a4005872a026894515b440b92c069033d2e89200 }


condition:
	$a0
}