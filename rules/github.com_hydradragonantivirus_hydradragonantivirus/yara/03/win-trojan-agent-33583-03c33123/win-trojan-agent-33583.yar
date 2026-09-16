rule Win_Trojan_Agent_33583
{
strings:
	$a0 = { 278af74ddc162f73ac49836997aaa0fcb5fff41eb9fe64fdb0231e67ef0e4ac5875d62af3b115887720cc5363a7cec322ba1461d36cfc2b136a1f66620225700c5e009abd72cfcd80e247022aedadc01cf0c }


condition:
	$a0
}