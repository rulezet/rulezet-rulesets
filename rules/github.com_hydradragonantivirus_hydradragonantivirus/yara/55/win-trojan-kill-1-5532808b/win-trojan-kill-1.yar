rule Win_Trojan_Kill_1
{
strings:
	$a0 = { 1e9900b91c00ba7c00cd21b442b0028b1e990033c933d2cd21b4408b1e9900b9420233d2cd21b4 }


condition:
	$a0
}