rule Win_Trojan_DonaldDick_10
{
strings:
	$a0 = { e9deffffff535152562eff15d4f440005068146441 }

	$a1 = { 6f6c6570726f632e657865006572736d67722e }


condition:
	$a0 and $a1
}