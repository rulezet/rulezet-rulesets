rule Win_Trojan_Barrotes_6
{
strings:
	$a0 = { 2e80bc20000175021e068cc02e01841e00b8daf0cd213cfe7504e996019006b82135cd212e891c2e8c4402078cc048 }


condition:
	$a0
}