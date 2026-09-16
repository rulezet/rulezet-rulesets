rule Win_Trojan_VGEN_77
{
strings:
	$a0 = { 8ed08ed88ec0bc007cfbb106a11304d3e02de0078ec0832e13040abe007c8bfeb90001f3a506b87d7c50cb061f }


condition:
	$a0
}