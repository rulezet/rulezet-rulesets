rule Win_Trojan_Zany_4
{
strings:
	$a0 = { 81ed07018db6b901bf000157a5a58d96bd01e88d00b44e8d969d01b90000cd217279e80400b44fe2f5b8023d8d96db }


condition:
	$a0
}