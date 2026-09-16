rule Win_Trojan_Ciudad_2
{
strings:
	$a0 = { 1e06eb01b0f40633c08ec026803e3c0315077503eb73908cd8488ed88b16030083ea32908bdab44aeb01b8cd }


condition:
	$a0
}