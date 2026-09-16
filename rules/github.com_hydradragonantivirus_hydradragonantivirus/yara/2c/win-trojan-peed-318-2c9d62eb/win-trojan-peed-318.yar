rule Win_Trojan_Peed_318
{
strings:
	$a0 = { eb27ab50525183c8ff4005998a400029db8b0829c05353ffd14093595a5801df }


condition:
	$a0
}