rule Win_Trojan_PCBB_1
{
strings:
	$a0 = { 5e81c6120089f7b96306b4c4ac32c4aae2fa }


condition:
	$a0
}