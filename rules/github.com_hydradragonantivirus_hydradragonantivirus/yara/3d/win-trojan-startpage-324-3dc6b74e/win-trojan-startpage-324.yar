rule Win_Trojan_Startpage_324
{
strings:
	$a0 = { 666c656d6f6e2e657865007b44393441414132412d43 }


condition:
	$a0
}