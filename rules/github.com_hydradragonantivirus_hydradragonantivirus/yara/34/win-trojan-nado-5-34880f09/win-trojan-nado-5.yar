rule Win_Trojan_Nado_5
{
strings:
	$a0 = { cd01e81600e800005d81ed0e01e8ce02e84502e80d }


condition:
	$a0
}