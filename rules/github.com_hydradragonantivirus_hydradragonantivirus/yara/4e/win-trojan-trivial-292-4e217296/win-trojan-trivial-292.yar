rule Win_Trojan_Trivial_292
{
strings:
	$a0 = { 4eba2a01b92700cd217219b42fcd218bf3b8023d8d541ecd2193b440b93000ba0001cd21b8414ccd21 }


condition:
	$a0
}