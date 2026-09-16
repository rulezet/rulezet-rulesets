rule Win_Trojan_Trojan_80
{
strings:
	$a0 = { 8104b900ff81e98104b4ddcd21eb23 }


condition:
	$a0
}