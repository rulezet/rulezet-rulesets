rule Win_Trojan_Lazar_1
{
strings:
	$a0 = { 437cb8ff30cd233dff307506b87f02eb0f9033c08ec0b704b313b880022689070e1f2e8b26 }


condition:
	$a0
}