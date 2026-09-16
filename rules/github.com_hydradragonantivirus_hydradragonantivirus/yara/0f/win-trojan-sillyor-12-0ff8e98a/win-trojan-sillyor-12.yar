rule Win_Trojan_SillyOR_12
{
strings:
	$a0 = { b44eba????cd21723ab80043ba9e00cd21890e????b80143b90000ba9e00cd21b8013dba9e00cd2193b440b94900ba0001cd21 }


condition:
	$a0
}