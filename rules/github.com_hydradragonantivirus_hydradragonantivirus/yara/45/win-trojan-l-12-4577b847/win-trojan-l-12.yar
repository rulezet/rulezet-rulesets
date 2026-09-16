rule Win_Trojan_L_12
{
strings:
	$a0 = { f05e75263ddf2e7504b8649fcf569c50be4a0afc2eac2a }


condition:
	$a0
}