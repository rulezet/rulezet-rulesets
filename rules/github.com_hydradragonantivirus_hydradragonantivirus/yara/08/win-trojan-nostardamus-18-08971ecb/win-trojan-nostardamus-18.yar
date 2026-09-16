rule Win_Trojan_Nostardamus_18
{
strings:
	$a0 = { 35e8f603891eba088c06bc081ec5368604ac3ccd74043c7775f78d5406b8db25e8d7034ec704cd }


condition:
	$a0
}