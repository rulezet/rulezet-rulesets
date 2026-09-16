rule Win_Trojan_Trance_4
{
strings:
	$a0 = { 0203dd32e4cd1a8817e8b2005b8bd3b8023ccd8072b28bd8b43eb90200badc0203d5cd80726a }


condition:
	$a0
}