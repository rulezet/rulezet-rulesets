rule Win_Trojan_Harakiri_1
{
strings:
	$a0 = { 484152414b495249207669727573219a000073005589e5 }


condition:
	$a0
}