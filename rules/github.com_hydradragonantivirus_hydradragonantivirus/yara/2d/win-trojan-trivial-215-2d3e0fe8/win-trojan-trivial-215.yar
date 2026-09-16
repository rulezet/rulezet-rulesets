rule Win_Trojan_Trivial_215
{
strings:
	$a0 = { 4eb90000ba2301cd217216b43cba9e00cd2193b440b92700ba0001cd21b44febe6c32a2e2a00 }


condition:
	$a0
}