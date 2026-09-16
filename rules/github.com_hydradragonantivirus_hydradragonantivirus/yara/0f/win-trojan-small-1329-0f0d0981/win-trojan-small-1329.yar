rule Win_Trojan_Small_1329
{
strings:
	$a0 = { 8d85bcefffff68b4e3001050e8639500008d85bcebffff508d85bcefffff50e85095000083c4108d45f0508d85d0fdffff50535368a4e30010ff75ec897df0ffd6 }


condition:
	$a0
}