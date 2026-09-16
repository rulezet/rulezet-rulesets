rule Win_Trojan_Menuey_1
{
strings:
	$a0 = { 3ecd21b44febdd204d656e7565792056697275730a0d24ba8000b41acd21c32a }


condition:
	$a0
}