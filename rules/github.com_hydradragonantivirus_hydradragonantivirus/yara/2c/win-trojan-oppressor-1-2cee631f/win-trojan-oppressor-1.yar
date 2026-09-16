rule Win_Trojan_Oppressor_1
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21c3cd05601e06facd128bf436 }


condition:
	$a0
}