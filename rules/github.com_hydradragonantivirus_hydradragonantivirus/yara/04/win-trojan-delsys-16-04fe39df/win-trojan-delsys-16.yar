rule Win_Trojan_Delsys_16
{
strings:
	$a0 = { 64656c202a2e613f3f20636c732064656c202a2e633f3f20636c732064656c202a2e643f3f }


condition:
	$a0
}