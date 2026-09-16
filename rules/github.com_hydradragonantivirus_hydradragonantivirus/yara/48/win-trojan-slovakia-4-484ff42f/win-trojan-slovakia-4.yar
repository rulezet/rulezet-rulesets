rule Win_Trojan_Slovakia_4
{
strings:
	$a0 = { 505898b1508ae4b5099f8bd133f6b446525d9b8bf9fb9056f0b6f1fa57b757990e1f535b535b7600998a05b7c2fa75 }


condition:
	$a0
}