rule Win_Trojan_Tornado_2
{
strings:
	$a0 = { e86101e80b0050b84d7c50cbe85501cd19 }


condition:
	$a0
}