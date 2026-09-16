rule Win_Trojan_Elvis_1
{
strings:
	$a0 = { bed40103360601ffe64bbe1501033606018a24 }


condition:
	$a0
}