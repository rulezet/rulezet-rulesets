rule Win_Trojan_AAEH_3
{
strings:
	$a0 = { 797973626c6f66 }

	$a1 = { e55dc20c00ff15e4104000cccccccccc558bec83ec18684618400064a1000000005064892500000000b85c000000e81d }


condition:
	$a0 and $a1
}