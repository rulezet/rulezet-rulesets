rule Win_Trojan_LaLa_1
{
strings:
	$a0 = { 2e8a042e30813f002e8a813f0089fe29c6434ee2eb }


condition:
	$a0
}