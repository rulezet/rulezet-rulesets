rule Win_Trojan_Vgen_111
{
strings:
	$a0 = { 80cd13882e0301880e040188160501b409ba0601cd218cc88ec0bb0000b90100ba8000b403a00401cd13fec53a }


condition:
	$a0
}