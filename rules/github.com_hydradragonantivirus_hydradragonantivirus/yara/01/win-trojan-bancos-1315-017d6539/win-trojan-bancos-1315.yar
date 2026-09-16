rule Win_Trojan_Bancos_1315
{
strings:
	$a0 = { 45a8d7bdc7b1375dc308bbe7823eaae5349d3f5aa1bcc82fec6c76dbb0837bd7f727a55cacdbfada3df0ea81844036974910a9f0d24ea03aef8904ae326686381184b04f5e49a5dcbf90801bf16ea993d0b4 }


condition:
	$a0
}