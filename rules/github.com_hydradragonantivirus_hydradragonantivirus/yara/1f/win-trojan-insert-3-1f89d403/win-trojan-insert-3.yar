rule Win_Trojan_Insert_3
{
strings:
	$a0 = { e540a30a01b91101bf1101be0000f3a4bf1701e83e00b440b91101ba1101cd211f5e5a5907 }


condition:
	$a0
}