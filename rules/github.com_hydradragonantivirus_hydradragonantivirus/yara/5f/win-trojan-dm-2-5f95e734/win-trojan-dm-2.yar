rule Win_Trojan_DM_2
{
strings:
	$a0 = { 80fc4b743380fc567419fe0480fc3d74 }


condition:
	$a0
}