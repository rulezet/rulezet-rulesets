rule Win_Trojan_Mini_20
{
strings:
	$a0 = { 0500108ec0b97d00ba00018bf233fff3a406b8190050cbb41acd211eba7701b90300b44ecd2172361f1eba1e01b802 }


condition:
	$a0
}