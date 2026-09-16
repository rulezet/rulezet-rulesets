rule Win_Trojan_Wit_4
{
strings:
	$a0 = { 02e8280080fe04751480fa0f750fb81010e770baa102e81300b0fee6648a6605b107ba9502cd }


condition:
	$a0
}