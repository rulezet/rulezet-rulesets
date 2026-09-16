rule Win_Trojan_MeiHua_1
{
strings:
	$a0 = { 2ec706400540009c580d0003509d90909090909090 }


condition:
	$a0
}