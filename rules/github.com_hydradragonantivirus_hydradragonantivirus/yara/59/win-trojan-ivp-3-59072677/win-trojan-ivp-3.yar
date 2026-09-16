rule Win_Trojan_IVP_3
{
strings:
	$a0 = { 03008d96a001cd213e80bea001e9742f3e8b86c301 }


condition:
	$a0
}