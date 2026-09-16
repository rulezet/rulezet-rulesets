rule Win_Trojan_Gen_28
{
strings:
	$a0 = { 08be0501b9be07900503018bd0e851005f07b440cd2126c745150000b440ba4902b90500cd21 }


condition:
	$a0
}