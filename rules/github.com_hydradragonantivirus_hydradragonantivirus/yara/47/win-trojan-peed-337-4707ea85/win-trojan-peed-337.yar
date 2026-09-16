rule Win_Trojan_Peed_337
{
strings:
	$a0 = { 8d1d4223ac00eb6848b9e3cbffff81c167450000ba200202 }


condition:
	$a0
}