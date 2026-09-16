rule Win_Trojan_Peed_9
{
strings:
	$a0 = { 81c0c959430068435304006822749800 }


condition:
	$a0
}