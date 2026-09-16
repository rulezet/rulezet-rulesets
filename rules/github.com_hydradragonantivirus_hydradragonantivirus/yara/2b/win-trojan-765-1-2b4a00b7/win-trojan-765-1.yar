rule Win_Trojan_765_1
{
strings:
	$a0 = { 0a268a1480ea40cd213dffff740e }


condition:
	$a0
}