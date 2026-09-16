rule Win_Trojan_V_37
{
strings:
	$a0 = { 89e461bae20a6627d9e42d29400c61e43f67a7e1a2e772c752ef7acf5a63ea0021 }


condition:
	$a0
}