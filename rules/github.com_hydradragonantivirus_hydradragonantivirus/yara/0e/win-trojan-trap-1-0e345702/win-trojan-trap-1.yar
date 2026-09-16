rule Win_Trojan_Trap_1
{
strings:
	$a0 = { 048b5c1c53b903003b5c1c74fb8b5c1ce2f6592bd903c3c1e3032bfb1fb9bc03c30e1f686d04 }


condition:
	$a0
}