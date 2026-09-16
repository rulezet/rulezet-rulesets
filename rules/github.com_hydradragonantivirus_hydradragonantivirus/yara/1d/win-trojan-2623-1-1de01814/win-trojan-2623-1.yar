rule Win_Trojan__2623_1
{
strings:
	$a0 = { 0c00b905008a0704148842f64346e2f5c642f600c7 }


condition:
	$a0
}