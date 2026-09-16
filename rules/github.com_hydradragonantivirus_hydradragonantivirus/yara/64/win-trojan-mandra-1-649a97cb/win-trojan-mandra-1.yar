rule Win_Trojan_Mandra_1
{
strings:
	$a0 = { cd21b43fb9120233d2fec4cd21b80042b90000ba0000 }


condition:
	$a0
}