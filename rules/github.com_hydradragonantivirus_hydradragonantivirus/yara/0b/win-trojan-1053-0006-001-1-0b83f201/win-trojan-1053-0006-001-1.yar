rule Win_Trojan__1053_0006_001_1
{
strings:
	$a0 = { 05e9802e6a0503b440b90300ba6905cd21b002e89dff2d07008bca8bd0b80042cd21b43fb9 }


condition:
	$a0
}