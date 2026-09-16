rule Win_Trojan_Kolya_2
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21b81035cd21891ed1008c06d300b81025ba }


condition:
	$a0
}