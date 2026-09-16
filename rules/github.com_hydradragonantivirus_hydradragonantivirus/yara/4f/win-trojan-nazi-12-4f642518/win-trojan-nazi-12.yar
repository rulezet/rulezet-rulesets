rule Win_Trojan_Nazi_12
{
strings:
	$a0 = { 052a2e636f6d052a2e6578655589e583ec04c646ff00bf }


condition:
	$a0
}