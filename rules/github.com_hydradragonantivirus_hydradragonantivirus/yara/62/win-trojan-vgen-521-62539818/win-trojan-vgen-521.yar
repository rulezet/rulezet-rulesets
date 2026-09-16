rule Win_Trojan_VGEN_521
{
strings:
	$a0 = { 2abf00018bf283c609b90300f3a452b42fcd218bfa2e895d1381c28901b41acd215a83c203e87b00e8a100b41a2e }


condition:
	$a0
}