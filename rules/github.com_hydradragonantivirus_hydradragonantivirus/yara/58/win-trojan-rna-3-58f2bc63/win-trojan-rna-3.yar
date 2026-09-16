rule Win_Trojan_RNA_3
{
strings:
	$a0 = { b8801c509a1103b700a3f2018916f401 }


condition:
	$a0
}