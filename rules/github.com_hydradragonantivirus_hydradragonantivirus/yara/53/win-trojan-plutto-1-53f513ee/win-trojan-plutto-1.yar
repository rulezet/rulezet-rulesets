rule Win_Trojan_Plutto_1
{
strings:
	$a0 = { b903008d943f05cd218dbc3f05b84d5a2e3905750bb4 }


condition:
	$a0
}