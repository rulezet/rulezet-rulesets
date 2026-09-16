rule Win_Trojan_Relzfu_1
{
strings:
	$a0 = { 8f01b40e3455cd10e2f4cd10ebfc5781c7e3008bf7bf0001 }


condition:
	$a0
}