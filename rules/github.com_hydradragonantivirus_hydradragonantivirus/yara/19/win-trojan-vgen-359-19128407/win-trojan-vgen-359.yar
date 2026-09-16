rule Win_Trojan_VGEN_359
{
strings:
	$a0 = { 0e1f07bab30ce8b71eba460ee8b11ebf330cb009e840193c0875034feb0d3c0d740e3c3072ec3c3977e8aae8781eeb }


condition:
	$a0
}