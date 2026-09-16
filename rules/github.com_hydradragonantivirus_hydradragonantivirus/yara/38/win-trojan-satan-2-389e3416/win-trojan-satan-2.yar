rule Win_Trojan_Satan_2
{
strings:
	$a0 = { d581c22102cd21b80242b900008bd1cd212d03008bf581 }


condition:
	$a0
}