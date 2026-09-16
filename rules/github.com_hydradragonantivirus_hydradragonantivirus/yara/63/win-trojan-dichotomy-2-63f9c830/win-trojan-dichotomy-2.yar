rule Win_Trojan_Dichotomy_2
{
strings:
	$a0 = { c480fc4c7432fecc80fc51740c80fc6274052eff2e8c03 }


condition:
	$a0
}