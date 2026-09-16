rule Win_Trojan_V_27
{
strings:
	$a0 = { fdff87e5f7dc87ec608bc1b9040002c45be2fb8b378bfe8bee83c10426803dcc7501ca26807c30cc9074f75b46e2ed }


condition:
	$a0
}