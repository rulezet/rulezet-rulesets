rule Win_Trojan_Right2Life_1
{
strings:
	$a0 = { fceb01908db61a008bfeb905038aa61f03ac32c4aae2fa }


condition:
	$a0
}