rule Win_Trojan_Delf_2284
{
strings:
	$a0 = { 558bec83c4f033c08945f0b8f43b0200e8571dffff33c05568263d02 }

	$a1 = { 6f6f45456f0ac26d0ac3 }

	$a2 = { 21726863666e716d64756a }


condition:
	$a0 and $a1 and $a2
}