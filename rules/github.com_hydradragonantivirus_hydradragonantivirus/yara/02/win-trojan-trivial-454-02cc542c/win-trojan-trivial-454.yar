rule Win_Trojan_Trivial_454
{
strings:
	$a0 = { b92000ba5101cd21b42fcd21061f8d571eb80043cd215152b80143b90000cd21b8023dcd218bd8b80057cd215152 }


condition:
	$a0
}