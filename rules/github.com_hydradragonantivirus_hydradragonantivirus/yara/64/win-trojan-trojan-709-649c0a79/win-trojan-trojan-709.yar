rule Win_Trojan_Trojan_709
{
strings:
	$a0 = { e9e4280000e8040000008be55dc3582d0a104000c36033c08b74242466813e4d }


condition:
	$a0
}