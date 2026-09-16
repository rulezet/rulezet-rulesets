rule Win_Trojan_Rikki_3
{
strings:
	$a0 = { cd21b43ecd21268f05a0f301a2f001a1f401a3f1012e8b16290159b80143cd218bfa32c0b90e }


condition:
	$a0
}