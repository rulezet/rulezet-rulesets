rule Win_Trojan_Agent_33053
{
strings:
	$a0 = { 5417ae516dffbff07f04fd03112f8bc28e0703b6fb6a9aad241294c601243c0fc1fffff6ffe91b64b80285cc20673bd48f2689b6c80442590d0e60b00177c30f1dff8dffff8c05723642 }


condition:
	$a0
}