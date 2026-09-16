rule Win_Trojan_V_6
{
strings:
	$a0 = { f8525cf6f8505c69acfa5d5b6ade555c1cdba47f5e28afe05a5ce37f5eee1ab2ee5a002858619b02 }


condition:
	$a0
}