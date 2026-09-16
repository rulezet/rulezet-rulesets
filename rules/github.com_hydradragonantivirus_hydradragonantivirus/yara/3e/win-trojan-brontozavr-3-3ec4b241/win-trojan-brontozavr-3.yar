rule Win_Trojan_Brontozavr_3
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21b81035cd21891eb9008c06bb00b81025bab500cd21 }


condition:
	$a0
}