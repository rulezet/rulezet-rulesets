rule Win_Trojan_Sepultura_1
{
strings:
	$a0 = { 6a00e2fc61b84202cd21e800005e83ee10bf420207 }


condition:
	$a0
}