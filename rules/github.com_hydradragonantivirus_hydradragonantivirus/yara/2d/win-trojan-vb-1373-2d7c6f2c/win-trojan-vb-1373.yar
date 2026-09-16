rule Win_Trojan_VB_1373
{
strings:
	$a0 = { ffcc3100051ec94fe2a0d7b242ae6a99d17ed1183c2eec6262fb9e684985b23344e38e8bac3a4fad339966cf11 }


condition:
	$a0
}