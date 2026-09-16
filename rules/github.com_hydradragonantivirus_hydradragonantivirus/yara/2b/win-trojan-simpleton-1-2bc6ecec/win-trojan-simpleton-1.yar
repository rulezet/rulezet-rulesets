rule Win_Trojan_Simpleton_1
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd210e07b409bac101cd21b431ba1e00cd21 }


condition:
	$a0
}