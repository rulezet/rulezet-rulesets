rule Win_Trojan_APPARATI_1
{
strings:
	$a0 = { 3f03d80500cd3f03080600cd3f032d0600cd3f034d06000000000a57494e4150502e455845 }


condition:
	$a0
}