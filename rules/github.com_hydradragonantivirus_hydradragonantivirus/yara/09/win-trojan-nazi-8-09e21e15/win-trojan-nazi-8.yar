rule Win_Trojan_Nazi_8
{
strings:
	$a0 = { 052a2e636f6d5589e583ec04c646ff00bf19010e57b820 }


condition:
	$a0
}