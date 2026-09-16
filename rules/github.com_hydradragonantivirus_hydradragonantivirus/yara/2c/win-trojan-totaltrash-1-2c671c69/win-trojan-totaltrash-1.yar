rule Win_Trojan_TotalTrash_1
{
strings:
	$a0 = { b430ba5249b90002cd218bec8b6efa81ed0c000bd2750d8bf533ffb92b02902ef3a674378cd8488ed833ff803d5a }


condition:
	$a0
}