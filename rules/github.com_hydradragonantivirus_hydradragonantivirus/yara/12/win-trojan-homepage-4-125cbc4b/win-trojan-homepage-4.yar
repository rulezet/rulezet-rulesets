rule Win_Trojan_Homepage_4
{
strings:
	$a0 = { 28666f6c64657226225c686f6d65706167652e68746d6c2e76627322 }


condition:
	$a0
}