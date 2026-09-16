rule Win_Trojan_Small_148
{
strings:
	$a0 = { ff803d4d741ab002cd21a38900e8ccffb189b440e8c3ffcd21b440b287e8b8ffb43ecd21 }


condition:
	$a0
}