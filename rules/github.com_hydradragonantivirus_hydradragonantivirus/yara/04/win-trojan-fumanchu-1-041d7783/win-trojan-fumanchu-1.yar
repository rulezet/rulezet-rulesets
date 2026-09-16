rule Win_Trojan_FuManchu_1
{
strings:
	$a0 = { ddbf0001be200803f72e8b8d2600cd }


condition:
	$a0
}