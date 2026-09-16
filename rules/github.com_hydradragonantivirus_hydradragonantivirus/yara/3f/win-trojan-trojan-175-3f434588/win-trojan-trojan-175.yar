rule Win_Trojan_Trojan_175
{
strings:
	$a0 = { 37fa33c08ed88ed0bc007cfbcd1248a31304 }


condition:
	$a0
}