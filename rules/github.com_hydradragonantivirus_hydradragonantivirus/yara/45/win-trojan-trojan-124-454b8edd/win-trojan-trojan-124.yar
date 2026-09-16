rule Win_Trojan_Trojan_124
{
strings:
	$a0 = { 8ed833d2b440e83600bbd0012e8b57022e8b0fb801 }


condition:
	$a0
}