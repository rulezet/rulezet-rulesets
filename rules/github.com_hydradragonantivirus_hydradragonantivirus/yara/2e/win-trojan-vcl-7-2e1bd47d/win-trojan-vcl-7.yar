rule Win_Trojan_VCL_7
{
strings:
	$a0 = { 0335cd21b425ba8c01cd2187d3cd21b8f2f9051000ba35 }


condition:
	$a0
}