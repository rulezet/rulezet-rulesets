rule Win_Trojan_Peed_83
{
strings:
	$a0 = { 685244040081e8010000 }


condition:
	$a0
}