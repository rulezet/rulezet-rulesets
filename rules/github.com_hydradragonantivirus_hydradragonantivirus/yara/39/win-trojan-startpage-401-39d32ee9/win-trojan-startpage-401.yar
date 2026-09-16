rule Win_Trojan_Startpage_401
{
strings:
	$a0 = { 626573747365617263682e6e65742ff6faff600a7068703f713d }


condition:
	$a0
}