rule Win_Trojan_Gen_24
{
strings:
	$a0 = { be0501b9b306900503018bd0e851005f07b440cd2126c745150000b440ba4902b90500cd21 }


condition:
	$a0
}