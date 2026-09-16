rule Win_Trojan_Birgit_25
{
strings:
	$a0 = { e2fdba2c02ffd2c353ba1402ffd25bb440b92c01ba0001cd2153ba1402ffd25bc3 }


condition:
	$a0
}