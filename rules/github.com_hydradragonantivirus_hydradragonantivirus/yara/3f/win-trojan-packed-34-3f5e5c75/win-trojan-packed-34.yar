rule Win_Trojan_Packed_34
{
strings:
	$a0 = { 60e8060000008b642408eb0c[0-20]902bff648f075fe800000000 }


condition:
	$a0
}