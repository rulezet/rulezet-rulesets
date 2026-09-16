rule Win_Trojan_Hi_8
{
strings:
	$a0 = { 50e800005d33c08ed883ed06813e6401d02e753dfa581f078ccb2e2b9ed0002e039ed6008ed32e8b8ed8008be12e }


condition:
	$a0
}