rule Win_Trojan_Fichv_1
{
strings:
	$a0 = { 0dac3207aa433bda7203bbbc01cf }


condition:
	$a0
}