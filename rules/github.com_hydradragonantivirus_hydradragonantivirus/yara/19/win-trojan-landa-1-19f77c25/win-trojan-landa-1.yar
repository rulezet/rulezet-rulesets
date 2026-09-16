rule Win_Trojan_Landa_1
{
strings:
	$a0 = { c7855cffffff08204000c78554ffffff080000008d9554ffffff8d4db4ff15fc1040008d4584508d4d94518d55a4526a10 }


condition:
	$a0
}