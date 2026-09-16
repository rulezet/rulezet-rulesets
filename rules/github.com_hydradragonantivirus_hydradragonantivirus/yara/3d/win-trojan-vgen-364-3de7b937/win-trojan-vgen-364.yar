rule Win_Trojan_VGEN_364
{
strings:
	$a0 = { b90001e2feb9eb09b805feebfc80c43bebf4b80335cd21b425ba8b01cd2187dacd21b8f2f9051000ba355983c210 }


condition:
	$a0
}