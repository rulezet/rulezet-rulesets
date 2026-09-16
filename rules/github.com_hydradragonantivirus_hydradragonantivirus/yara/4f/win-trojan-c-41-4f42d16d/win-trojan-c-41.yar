rule Win_Trojan_C_41
{
strings:
	$a0 = { 3e0a01007415e9010000a00a01bb1c01ba5d0287d12e300743e2fa }


condition:
	$a0
}