rule Win_Trojan_Small_742
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd2133f6ebb6e90000e9c6 }


condition:
	$a0
}