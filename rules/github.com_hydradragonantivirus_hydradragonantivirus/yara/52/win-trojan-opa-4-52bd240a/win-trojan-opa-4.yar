rule Win_Trojan_Opa_4
{
strings:
	$a0 = { 09010001b82135cd21891e03018c060501b82125ba1001cd21ba7201b80031cd21 }


condition:
	$a0
}