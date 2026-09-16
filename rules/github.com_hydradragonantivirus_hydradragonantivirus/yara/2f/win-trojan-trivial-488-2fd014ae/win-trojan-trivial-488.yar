rule Win_Trojan_Trivial_488
{
strings:
	$a0 = { 8d162901cd21721cb8023dba9e00cd21bb9c40b99c015350ba00015b58cd21b89c4febdccd202a2e636f4d0020 }


condition:
	$a0
}