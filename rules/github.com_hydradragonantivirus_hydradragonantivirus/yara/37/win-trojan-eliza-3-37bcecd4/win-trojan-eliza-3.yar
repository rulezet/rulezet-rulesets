rule Win_Trojan_Eliza_3
{
strings:
	$a0 = { 2acd2180fa0d75133c05750fc6066d }


condition:
	$a0
}