rule Win_Trojan_SillyC_183
{
strings:
	$a0 = { 5b3d4d5a7503eb4d9080fddd7502ebf6b8024233c9 }


condition:
	$a0
}