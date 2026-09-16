rule Win_Trojan__0155_0006_001_1
{
strings:
	$a0 = { cd21b8004233c999cd21ba150459b440cd21b801575a59cd21b43ecd21585a1f59cd21071f5f }


condition:
	$a0
}