rule Win_Trojan_Hi_5
{
strings:
	$a0 = { 50e800005d33c08ed883ed06813e6401d42e7538fa581f078ccb2e2b9ebf002e039ec5008ed32e8b8ec7008be12e }


condition:
	$a0
}