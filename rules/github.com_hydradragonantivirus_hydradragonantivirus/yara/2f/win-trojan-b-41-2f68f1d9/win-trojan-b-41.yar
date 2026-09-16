rule Win_Trojan_B_41
{
strings:
	$a0 = { 0e1fe800005d81ed11058a86050590b9fe038db60301300446e2fb }


condition:
	$a0
}