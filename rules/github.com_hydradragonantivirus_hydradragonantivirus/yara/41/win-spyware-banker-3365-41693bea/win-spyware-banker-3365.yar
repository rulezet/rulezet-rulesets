rule Win_Spyware_Banker_3365
{
strings:
	$a0 = { f105561be4d6dbf11a166004d43f9026e8bae74b70b2951b8bc1064cae2425bfa2db1e41172993b8ebe1ffd83bc9c6ca8905d9a54f3e3d062d4888b36b87673d2bfbe6ef3d08 }


condition:
	$a0
}