rule Win_Trojan_Violator_12
{
strings:
	$a0 = { f2b80fffcd213d01017503e91902b4 }


condition:
	$a0
}