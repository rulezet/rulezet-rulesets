rule Win_Trojan_Silence_2
{
strings:
	$a0 = { 4459b9ec01be1401b44228244680c4c7e2f8 }


condition:
	$a0
}