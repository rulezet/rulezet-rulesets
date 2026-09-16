rule Win_Trojan_Blast_1
{
strings:
	$a0 = { 9c58f6c4017403e998001eb002e6218cda83c2108eda8ec2bb0a20ba000085d27429b40133ff33f6b900f0ac32c4 }


condition:
	$a0
}