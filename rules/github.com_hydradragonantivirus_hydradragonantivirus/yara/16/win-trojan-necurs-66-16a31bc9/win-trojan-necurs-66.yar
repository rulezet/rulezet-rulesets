rule Win_Trojan_Necurs_66
{
strings:
	$a0 = { 2345c88945c48b45c4a37c68410068dc674100e820feffff598945f4837df4007405 }


condition:
	$a0
}