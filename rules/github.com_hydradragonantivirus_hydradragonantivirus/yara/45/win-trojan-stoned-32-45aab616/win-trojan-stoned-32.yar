rule Win_Trojan_Stoned_32
{
strings:
	$a0 = { dfc4164c0089164c038c064e03fa8ed7be007c8be6 }


condition:
	$a0
}