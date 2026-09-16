rule Win_Trojan_C_81
{
strings:
	$a0 = { fe52e417f1f0badd101f46528d961aef527ea102d20874b6fa68f056e810e2183fa916f2b023 }


condition:
	$a0
}