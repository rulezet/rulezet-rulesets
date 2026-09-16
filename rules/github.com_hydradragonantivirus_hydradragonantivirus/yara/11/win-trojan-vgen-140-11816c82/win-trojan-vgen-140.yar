rule Win_Trojan_VGEN_140
{
strings:
	$a0 = { 90e8d606ec3de0b90eeab61dfe712fb7cec876a2827f4532d53c30bc0ee67bd6b5be0f9510bf0e9510ae0e3208ae0e }


condition:
	$a0
}