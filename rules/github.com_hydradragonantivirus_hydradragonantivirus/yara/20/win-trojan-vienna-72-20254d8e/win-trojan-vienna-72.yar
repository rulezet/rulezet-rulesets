rule Win_Trojan_Vienna_72
{
strings:
	$a0 = { 4eba1f0003d6b90300cd21eb04b44fcd217302eb9f8b84 }


condition:
	$a0
}