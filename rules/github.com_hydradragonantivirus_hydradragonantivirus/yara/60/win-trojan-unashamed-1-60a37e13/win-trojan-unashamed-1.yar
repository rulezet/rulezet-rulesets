rule Win_Trojan_Unashamed_1
{
strings:
	$a0 = { 8be68bfbb90300298c13888b841388d0e1d3e0b900 }


condition:
	$a0
}