rule Win_Trojan_Mybot_5489
{
strings:
	$a0 = { 903e7b3a17345bdec84deacd55054262e5dd12e31909c370392ce6d212fe0f959d875731e6527df2f28dfbc6d5e9010a78751c43b7bbabae6c3acb0acf3510d489bfa749b7f1 }


condition:
	$a0
}