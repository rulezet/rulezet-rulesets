rule Win_Trojan_Tiny_Di_1
{
strings:
	$a0 = { 390281c65b01b9dc00d1e973014e8bfead33c3abe2fa }


condition:
	$a0
}