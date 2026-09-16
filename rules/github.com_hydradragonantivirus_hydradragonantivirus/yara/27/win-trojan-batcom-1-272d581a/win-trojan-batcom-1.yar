rule Win_Trojan_BatCom_1
{
strings:
	$a0 = { 854f07494a484b1f4ea1e62c89d43898e24f91896d6f8989461e43404241064784e3a1183ca34f91 }


condition:
	$a0
}