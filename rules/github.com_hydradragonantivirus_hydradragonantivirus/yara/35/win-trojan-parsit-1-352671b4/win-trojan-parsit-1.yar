rule Win_Trojan_Parsit_1
{
strings:
	$a0 = { 048bd681eaff02cd21721f3d6c04 }


condition:
	$a0
}