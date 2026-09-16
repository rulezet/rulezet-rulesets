rule Win_Trojan_Terminator_8
{
strings:
	$a0 = { 32b2f6e9e49ffd92f00da3e0fed1f80e8716f1a17e3542f6 }


condition:
	$a0
}