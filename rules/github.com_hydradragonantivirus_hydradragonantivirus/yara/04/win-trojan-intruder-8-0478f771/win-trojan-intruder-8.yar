rule Win_Trojan_Intruder_8
{
strings:
	$a0 = { 0e1fb41aba0000cd21e820007203e88c00061fba8000b41acd2158fa2e8e164d002e8b264f00fb2eff2e5300ba4700 }


condition:
	$a0
}