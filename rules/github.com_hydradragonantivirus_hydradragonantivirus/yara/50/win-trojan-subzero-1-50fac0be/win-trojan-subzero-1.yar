rule Win_Trojan_Subzero_1
{
strings:
	$a0 = { b83f2c32273227cd213dadde753281fb5a53752c161f1607b800011650b8000033c933d233db33f633ffcb }


condition:
	$a0
}