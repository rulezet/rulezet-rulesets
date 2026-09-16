rule Win_Trojan_Small_1830
{
strings:
	$a0 = { 5657be2c1040008d7df8a568040100008d85f4feffffa45033ff57ff151c10400068281040008d85f4feffff50ff1518104000 }


condition:
	$a0
}