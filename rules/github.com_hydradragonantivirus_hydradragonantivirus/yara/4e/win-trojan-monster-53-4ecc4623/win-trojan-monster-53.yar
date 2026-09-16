rule Win_Trojan_Monster_53
{
strings:
	$a0 = { 803654????eb00f30302be????8034??46e2fa }


condition:
	$a0
}