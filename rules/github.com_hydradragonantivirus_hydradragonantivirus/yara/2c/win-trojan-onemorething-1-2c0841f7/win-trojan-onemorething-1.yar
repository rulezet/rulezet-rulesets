rule Win_Trojan_Onemorething_1
{
strings:
	$a0 = { 8b3601018dbc1701b9890180352a47e2fa }


condition:
	$a0
}