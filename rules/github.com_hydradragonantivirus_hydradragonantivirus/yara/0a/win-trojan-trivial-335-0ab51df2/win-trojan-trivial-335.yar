rule Win_Trojan_Trivial_335
{
strings:
	$a0 = { 023dba9e00cd21b740ba00019388e1cd21b43ecd21b44f }


condition:
	$a0
}