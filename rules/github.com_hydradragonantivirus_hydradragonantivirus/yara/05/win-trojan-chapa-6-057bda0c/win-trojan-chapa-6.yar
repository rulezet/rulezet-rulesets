rule Win_Trojan_Chapa_6
{
strings:
	$a0 = { 7c014d567429e869ff2ec606130000b440b93c020e1f33d20ee819ffe85fffb440b93c02ba00bf }


condition:
	$a0
}