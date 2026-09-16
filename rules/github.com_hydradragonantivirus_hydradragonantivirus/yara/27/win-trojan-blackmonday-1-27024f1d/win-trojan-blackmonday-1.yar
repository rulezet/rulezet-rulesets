rule Win_Trojan_BlackMonday_1
{
strings:
	$a0 = { ac009c0650ea0000000033c08ed88f0602008f060000fb }


condition:
	$a0
}