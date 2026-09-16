rule Win_Trojan_Gen_96
{
strings:
	$a0 = { 0184aa022e8384aa0210061eb4fecd }


condition:
	$a0
}