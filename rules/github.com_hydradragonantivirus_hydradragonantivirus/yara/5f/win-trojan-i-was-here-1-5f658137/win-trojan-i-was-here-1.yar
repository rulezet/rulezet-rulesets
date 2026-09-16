rule Win_Trojan_I_Was_Here_1
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd210e072ec706c403c4cc2e81 }


condition:
	$a0
}