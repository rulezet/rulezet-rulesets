rule Win_Trojan_Jerusalem_48
{
strings:
	$a0 = { ffcd213d524f7512b4eefcbf0001be62062e8b8d120003 }


condition:
	$a0
}