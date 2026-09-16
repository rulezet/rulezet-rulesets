rule Win_Trojan_MW_1
{
strings:
	$a0 = { 05fd3007fd0403f03007f00406f0340390fec0f043f0e2eaf8c3e6 }


condition:
	$a0
}