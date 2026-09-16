rule Win_Trojan_HumbleGuys_1
{
strings:
	$a0 = { 6d652e2e2e9a000032005589e531c09a7c0232009ae4073200bf46011e57bfac010e5731c050 }


condition:
	$a0
}