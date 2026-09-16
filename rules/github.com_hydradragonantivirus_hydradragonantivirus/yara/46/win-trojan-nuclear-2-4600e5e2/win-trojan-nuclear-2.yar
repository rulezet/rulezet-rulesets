rule Win_Trojan_Nuclear_2
{
strings:
	$a0 = { 0800550001000b00ffff363a0000f300000005000000363a }


condition:
	$a0
}