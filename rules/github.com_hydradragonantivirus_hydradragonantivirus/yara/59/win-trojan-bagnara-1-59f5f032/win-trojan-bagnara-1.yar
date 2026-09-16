rule Win_Trojan_Bagnara_1
{
strings:
	$a0 = { d6ebfcfdf9a302a1b207b146bdad0ab31b0cc02fb10710add1179ed93ee9e5e9bfa4df1dbc862227 }


condition:
	$a0
}