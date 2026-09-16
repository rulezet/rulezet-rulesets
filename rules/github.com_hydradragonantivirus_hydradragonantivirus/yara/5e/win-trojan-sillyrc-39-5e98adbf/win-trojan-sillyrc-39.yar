rule Win_Trojan_SillyRC_39
{
strings:
	$a0 = { 2135cd21be000189f7b91000fcf3a675318c06f202c706f0022001ff2ef0021e07b90002bf00018b36f40281c60001 }


condition:
	$a0
}