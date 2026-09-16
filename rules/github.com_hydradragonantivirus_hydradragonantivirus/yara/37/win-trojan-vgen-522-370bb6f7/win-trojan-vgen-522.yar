rule Win_Trojan_VGEN_522
{
strings:
	$a0 = { bf00018bf283c609b90300f3a452b42fcd218bfa2e895d0c81c2ac01b41acd21b42acd212e894d0e2e8955104942b4 }


condition:
	$a0
}