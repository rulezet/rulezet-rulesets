rule Win_Trojan_FathMac_4
{
strings:
	$a0 = { 0189c0b9d20681e9280189db89d2268a02345c26880288db0500004683eb0088f6e2e780ed00 }


condition:
	$a0
}