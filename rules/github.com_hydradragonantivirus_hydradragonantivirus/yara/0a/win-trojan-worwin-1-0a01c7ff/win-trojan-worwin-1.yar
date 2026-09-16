rule Win_Trojan_Worwin_1
{
strings:
	$a0 = { 4100f7266a2f8bf881c76f221e57b84000509a5408c700eb04ff066a2fa1682f3b46fe759889ec }


condition:
	$a0
}