rule Win_Trojan_DM_7
{
strings:
	$a0 = { 743380fc567419fe0480fc3d7412fe0480fc3e751c }


condition:
	$a0
}