rule Win_Trojan_Small_182
{
strings:
	$a0 = { 56afb026b3498ec0b13bf3a48ed987013c267406ab8cc08701ab0e070e1f5f29f1f3a4ebda6089d6ac3de940750a1e }


condition:
	$a0
}