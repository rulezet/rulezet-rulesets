rule Win_Trojan_Peed_70
{
strings:
	$a0 = { 680fccffffe9 }


condition:
	$a0
}