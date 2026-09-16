rule Win_Trojan_G_24
{
strings:
	$a0 = { 3cff7403abeb024747e2f4594646e2e3b801b88e }


condition:
	$a0
}