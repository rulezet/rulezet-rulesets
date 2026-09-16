rule Win_Trojan_HNY_1
{
strings:
	$a0 = { 8bd581c20b01b9fa00cd21b8004233c933d2cd21b440 }


condition:
	$a0
}