rule Win_Trojan_Phardera_4
{
strings:
	$a0 = { 010100558e0000000001006a080000c3060000020000006a08 }


condition:
	$a0
}