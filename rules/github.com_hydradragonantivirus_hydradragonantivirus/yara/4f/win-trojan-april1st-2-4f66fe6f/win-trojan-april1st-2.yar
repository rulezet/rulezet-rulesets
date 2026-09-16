rule Win_Trojan_April1st_2
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21b44abbad04bcad041e0783c30f }


condition:
	$a0
}