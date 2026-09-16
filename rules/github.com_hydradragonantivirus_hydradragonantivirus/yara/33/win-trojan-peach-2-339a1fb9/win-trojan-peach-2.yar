rule Win_Trojan_Peach_2
{
strings:
	$a0 = { cd21891e6f038c067103baa102b8 }


condition:
	$a0
}