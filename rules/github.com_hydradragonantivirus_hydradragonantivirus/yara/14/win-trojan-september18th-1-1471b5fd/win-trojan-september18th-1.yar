rule Win_Trojan_September18th_1
{
strings:
	$a0 = { 750232c03cff7502b0015051cd2683c4 }


condition:
	$a0
}