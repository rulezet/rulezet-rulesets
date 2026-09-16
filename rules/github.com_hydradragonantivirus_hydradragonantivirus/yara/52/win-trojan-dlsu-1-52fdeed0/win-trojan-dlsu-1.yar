rule Win_Trojan_Dlsu_1
{
strings:
	$a0 = { 803e770114751abe7801b91600f61446e2fbba7801b409cd21c606770100e8fe00a17201a36c01b42fcd218c }


condition:
	$a0
}