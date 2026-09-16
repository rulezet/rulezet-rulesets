rule Win_Trojan_Orudis_2
{
strings:
	$a0 = { 2a212a212a0a0d242a2e636f6d002a2e657865002e2e00cd20 }


condition:
	$a0
}