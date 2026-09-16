rule Win_Trojan_Trivial_63
{
strings:
	$a0 = { 0600b44eba6201cd210ac07551ba9e00b8023dcd218bd8b80042b90000ba0000cd21b43fb90100ba6801cd2181 }


condition:
	$a0
}