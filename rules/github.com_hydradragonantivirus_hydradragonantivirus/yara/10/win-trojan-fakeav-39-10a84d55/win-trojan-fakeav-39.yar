rule Win_Trojan_Fakeav_39
{
strings:
	$a0 = { 5051585952535a5b555051585953525b5a508bc25a5153595b8bec508bc25a51 }


condition:
	$a0
}