rule Win_Trojan_Tox_1
{
strings:
	$a0 = { 60e800005d81ed????b000b9??008db6????2e300446e2fa }


condition:
	$a0
}