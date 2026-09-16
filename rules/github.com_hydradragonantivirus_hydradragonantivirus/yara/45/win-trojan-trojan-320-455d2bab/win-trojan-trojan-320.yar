rule Win_Trojan_Trojan_320
{
strings:
	$a0 = { 5b0003d6b90300cd21eb04b44fcd217302eb9f8b84 }


condition:
	$a0
}