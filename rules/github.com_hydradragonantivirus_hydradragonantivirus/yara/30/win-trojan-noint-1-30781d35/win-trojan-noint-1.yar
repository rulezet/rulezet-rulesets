rule Win_Trojan_NoInt_1
{
strings:
	$a0 = { 04b106d3e08ec036a38c00b8da00 }


condition:
	$a0
}