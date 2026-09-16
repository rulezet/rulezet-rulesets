rule Win_Trojan_AfterShake_1
{
strings:
	$a0 = { ffbf85010e57b8100050bf52001e579a00002300833e921900754fbf70001e57bf88010e57 }


condition:
	$a0
}