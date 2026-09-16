rule Win_Trojan_Sahand_1
{
strings:
	$a0 = { 5a595b585ec38d018ccb8edb4e45b42fcd210653bab804b41acd21c60695046d90c60696 }


condition:
	$a0
}