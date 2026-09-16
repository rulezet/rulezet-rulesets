rule Win_Trojan_Birgit_3
{
strings:
	$a0 = { c9bab401cd217226b8013dba9e00cd2193b44050b93100ba0001cd2158b98800bac301cd21 }


condition:
	$a0
}