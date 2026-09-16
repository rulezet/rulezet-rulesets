rule Win_Trojan_VGEN_595
{
strings:
	$a0 = { 9090b801faba4559cd16e800008bfc368b2d81ed0f0144448d9e2b02ff374343ff37b41a8d962f02cd21ccb44e8d }


condition:
	$a0
}