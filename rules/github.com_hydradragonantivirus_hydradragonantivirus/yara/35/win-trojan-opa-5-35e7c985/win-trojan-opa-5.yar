rule Win_Trojan_Opa_5
{
strings:
	$a0 = { 40008ec0bb0c0026833fff742326c707ffff07b82135cd21891e03018c060501b82125ba1001cd21ba6400b80031 }


condition:
	$a0
}