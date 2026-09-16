rule Win_Trojan_VGEN_66
{
strings:
	$a0 = { b801faba4559cd16e800005d81ed1301eb02cd208db6d901bf0001a5a50e1f8d965202b41acd21b801352d0010bb }


condition:
	$a0
}