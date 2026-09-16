rule Win_Trojan_Small_5131
{
strings:
	$a0 = { 68b81940008d4dece8cc0300008d45ec8bcf50c645fc03e88de2ffff }


condition:
	$a0
}