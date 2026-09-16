rule Win_Trojan_DeltreeY_7
{
strings:
	$a0 = { 6563686f206f66660d0a636c730d0a64656c74726565202f7920633a5c2a2e2a203e6e756c0d0a }


condition:
	$a0
}