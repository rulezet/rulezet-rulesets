rule Win_Trojan_Vgen_117
{
strings:
	$a0 = { 905b6c99876bf584575d2ee19d2ea58c6b8664894d9624c5488b242e70e29947e2866d2e8c242e852e7b70e299c5 }


condition:
	$a0
}