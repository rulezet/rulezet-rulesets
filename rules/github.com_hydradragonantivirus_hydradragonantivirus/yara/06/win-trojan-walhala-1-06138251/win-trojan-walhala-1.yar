rule Win_Trojan_Walhala_1
{
strings:
	$a0 = { 10b44acd21bb0010b448cd2150b02aa20020b02ea20120b063a20220b06fa20320b06da20420b000a20520bae203 }


condition:
	$a0
}