rule Win_Trojan_SillyC_214
{
strings:
	$a0 = { 740881beee034d5a7503b137c3b8024233c933d2cd21 }


condition:
	$a0
}