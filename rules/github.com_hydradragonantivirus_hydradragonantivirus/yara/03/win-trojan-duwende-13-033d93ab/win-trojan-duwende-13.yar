rule Win_Trojan_Duwende_13
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd211f1e0783c6[4-5]1e03 }


condition:
	$a0
}