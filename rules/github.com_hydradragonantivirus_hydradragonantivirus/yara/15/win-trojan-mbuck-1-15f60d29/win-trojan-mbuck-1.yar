rule Win_Trojan_MBuck_1
{
strings:
	$a0 = { 0400052a2e6578655589e5bf91010e57b8210050bf52001e579a42002500833e7e0c00751f803e }


condition:
	$a0
}