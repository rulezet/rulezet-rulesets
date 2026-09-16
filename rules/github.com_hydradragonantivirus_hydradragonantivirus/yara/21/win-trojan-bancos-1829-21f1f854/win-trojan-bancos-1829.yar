rule Win_Trojan_Bancos_1829
{
strings:
	$a0 = { 36d8364460eeaf28c393f953af481b95f4e73fe0098d89ba5202c4abbf9088bfea495994c5c8f790bdff30b882a4d5b09cf6828039ec348e6f4fb0dee78bcc4e8b531a27812c }


condition:
	$a0
}