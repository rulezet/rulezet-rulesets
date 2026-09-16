rule Win_Trojan_Small_4456
{
strings:
	$a0 = { 83ec04b892cfbdfff7d089e28902ba22 }


condition:
	$a0
}