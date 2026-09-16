rule Win_Trojan_Trivial_348
{
strings:
	$a0 = { cd217227eb0790b44fcd21721eba6801b8023dcd218bd8b94800ba0001b440cd218b1e4801 }


condition:
	$a0
}