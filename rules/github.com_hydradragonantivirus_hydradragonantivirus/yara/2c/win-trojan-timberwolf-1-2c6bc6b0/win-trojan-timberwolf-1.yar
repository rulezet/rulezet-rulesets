rule Win_Trojan_TimberWolf_1
{
strings:
	$a0 = { 02bacefacd21e82500b92202bacefae82c005ae80c00 }


condition:
	$a0
}