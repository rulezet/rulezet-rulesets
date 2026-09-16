rule Win_Trojan_AT_4
{
strings:
	$a0 = { 4233c9cdb4b4408d54ffb103892ccdb4b43ecdb41f61ea }


condition:
	$a0
}