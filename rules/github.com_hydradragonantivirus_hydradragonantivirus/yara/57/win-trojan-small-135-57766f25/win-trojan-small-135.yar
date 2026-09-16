rule Win_Trojan_Small_135
{
strings:
	$a0 = { be0201bf4203fda7fc0e56f3a4ea57030000741056be84005626a526a55fb83400abab5e5f571e078bcc2b }


condition:
	$a0
}