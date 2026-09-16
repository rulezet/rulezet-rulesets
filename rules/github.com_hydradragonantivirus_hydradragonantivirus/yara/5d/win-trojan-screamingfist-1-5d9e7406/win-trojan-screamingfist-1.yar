rule Win_Trojan_ScreamingFist_1
{
strings:
	$a0 = { 02fcf3a48ed9faa38600c70684009c01fbb8ff3dcd21 }


condition:
	$a0
}