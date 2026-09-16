rule Win_Trojan_VCLYankee2_1
{
strings:
	$a0 = { e90000e800005d81ed06018db61403bf000157a5a48bfd8bec81ec8000b42fcd2153b4 }


condition:
	$a0
}