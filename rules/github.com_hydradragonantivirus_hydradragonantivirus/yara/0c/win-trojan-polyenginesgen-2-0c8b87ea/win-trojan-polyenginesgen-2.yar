rule Win_Trojan_PolyEngineSGen_2
{
strings:
	$a0 = { fb01cd21e8f905b9320051803ef401397406fe06f401eb09c606f40130fe06f301b43c33c9baed01cd217302eb }


condition:
	$a0
}