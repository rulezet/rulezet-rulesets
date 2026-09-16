rule Win_Trojan_Dead_7
{
strings:
	$a0 = { 745280fc3d7507e812007207eb463dadde74052eff }


condition:
	$a0
}