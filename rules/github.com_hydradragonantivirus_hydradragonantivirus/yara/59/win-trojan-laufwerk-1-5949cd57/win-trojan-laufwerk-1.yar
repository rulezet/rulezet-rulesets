rule Win_Trojan_Laufwerk_1
{
strings:
	$a0 = { 018edafa8b2698248e169a24fba396245dca0800b44dcd21cb000000ba87018eda8c06380033 }


condition:
	$a0
}