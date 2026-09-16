rule Win_Trojan_RDX_1
{
strings:
	$a0 = { 0157478b3503f74e4fa5a4061eb850008ec033ffb9570126803dbf7419f3a4b800008ed8be8400bf5701a5a5c744 }


condition:
	$a0
}