rule Win_Trojan_ICQ_3
{
strings:
	$a0 = { 4f5448455220494351204558504c4f49540004ffffff00057800e001d7 }


condition:
	$a0
}