rule Win_Trojan_Bestia_1
{
strings:
	$a0 = { 010050e85602598d46c850b8270050b8ad0050e8980183c406e914018d46e650ff76fee8911b59 }


condition:
	$a0
}