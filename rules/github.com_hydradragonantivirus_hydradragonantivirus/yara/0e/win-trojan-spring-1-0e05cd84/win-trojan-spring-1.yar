rule Win_Trojan_Spring_1
{
strings:
	$a0 = { f6e82900071f8cc805010050b800005033c0cbbe204de81400bb0001c707e914c747024e48c64704650e0753c3 }


condition:
	$a0
}