rule Win_Trojan_Peed_389
{
strings:
	$a0 = { 89c28d9417bd0c000081c22144000081fa214400000f849500000081fa63a100 }


condition:
	$a0
}