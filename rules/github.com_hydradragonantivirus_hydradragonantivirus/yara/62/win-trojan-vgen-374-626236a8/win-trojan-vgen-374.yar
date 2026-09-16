rule Win_Trojan_VGEN_374
{
strings:
	$a0 = { 8ed08ed88ec0bc007cfbb106a11304d3e02de0078ec0832e130402be007c8bfeb90001f3a506b8707c50cb061f }


condition:
	$a0
}