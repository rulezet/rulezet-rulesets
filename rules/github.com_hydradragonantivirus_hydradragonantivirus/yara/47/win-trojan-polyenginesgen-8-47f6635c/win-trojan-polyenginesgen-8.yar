rule Win_Trojan_PolyEngineSGen_8
{
strings:
	$a0 = { 01e82f00b43cb90000ba3201cd2193b440ba2802b91800cd21b43ecd21fe06320159e2d3cd20 }


condition:
	$a0
}