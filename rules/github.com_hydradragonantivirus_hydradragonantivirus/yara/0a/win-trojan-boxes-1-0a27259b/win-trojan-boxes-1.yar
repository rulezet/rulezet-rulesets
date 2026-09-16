rule Win_Trojan_Boxes_1
{
strings:
	$a0 = { 2a01052c012d0301a32601c6062501e9c6062801e9ba2501b440b90500cd21730ee901ffba0001 }


condition:
	$a0
}