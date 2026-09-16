rule Win_Trojan_Sly_1
{
strings:
	$a0 = { 9a00008c005589e5b800029acd028c0081ec0002e87cfcbf5a031e57bf9a050e5731c0509a70068c008dbe00fe16578d }


condition:
	$a0
}