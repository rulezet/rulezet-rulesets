rule Win_Trojan_Kitana_5
{
strings:
	$a0 = { 039399b280cd13381fc747fe55aab3029675eec30e1f87deff0e1304cd12c1e0068ec033ffb178 }


condition:
	$a0
}