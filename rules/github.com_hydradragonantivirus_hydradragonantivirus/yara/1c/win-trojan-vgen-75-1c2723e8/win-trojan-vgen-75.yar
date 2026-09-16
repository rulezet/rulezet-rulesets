rule Win_Trojan_Vgen_75
{
strings:
	$a0 = { 9090bd00001e06b43fbbffffcd213dffff746433c0501f06c40684002e8986dc012e8c86de01078cc0488ed8803e }


condition:
	$a0
}