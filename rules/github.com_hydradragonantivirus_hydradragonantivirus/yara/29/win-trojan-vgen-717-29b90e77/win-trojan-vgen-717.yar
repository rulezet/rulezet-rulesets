rule Win_Trojan_VGEN_717
{
strings:
	$a0 = { ee03bf0001fc501e065756b430cd2186e03d0a037247b8e033cd2180fca5743d8cc0488ed833db803f5a75318b47 }


condition:
	$a0
}