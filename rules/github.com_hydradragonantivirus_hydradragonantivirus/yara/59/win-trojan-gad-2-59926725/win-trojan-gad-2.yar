rule Win_Trojan_Gad_2
{
strings:
	$a0 = { 8bfe8bb48402b986025651f3a4595f2ac0f3aacbe80c0054686520526576656e676572fc5e81ee1900bf0001b8cf }


condition:
	$a0
}