rule Win_Trojan_Vgen_106
{
strings:
	$a0 = { 686f206f66660d0a63747479206e756c0d0a72656d20205f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f }


condition:
	$a0
}