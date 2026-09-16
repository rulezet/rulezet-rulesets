rule Win_Trojan_Nuclear_62
{
strings:
	$a0 = { 636c6561725f5241545f426574615f370000ff25fc8543008bc0ff25f48543008bc0 }


condition:
	$a0
}