rule Win_Trojan_Unashamed_2
{
strings:
	$a0 = { b900018ec0fcadabe2fcb80900be8101bf4c01e82001 }


condition:
	$a0
}