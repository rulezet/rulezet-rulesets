rule Win_Trojan_Peed_105
{
strings:
	$a0 = { 6dc2400087d36a016a026a006a006a056a }


condition:
	$a0
}