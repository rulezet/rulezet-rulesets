rule Win_Trojan_Peed_111
{
strings:
	$a0 = { 68d197faffe9a8000000f7db29dff7db01de89c3eb23f7da291424c35589e5ad83ee014e4e4e }


condition:
	$a0
}