rule Win_Trojan_C_79
{
strings:
	$a0 = { 117611b87ae1e8cffe590bc0846917d5eb18d0e89080ff55440bff74d04646833c1fa40075b7e8 }


condition:
	$a0
}