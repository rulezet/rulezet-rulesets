rule Win_Trojan_Youth_1
{
strings:
	$a0 = { 59b9ec01be????b4??28244680c4??e2f8 }


condition:
	$a0
}