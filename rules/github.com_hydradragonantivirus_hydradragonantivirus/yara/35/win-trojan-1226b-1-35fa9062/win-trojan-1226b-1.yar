rule Win_Trojan_1226B_1
{
strings:
	$a0 = { 03bf0009e81effe81bffbb3f00baff008ac38bf38bb0 }


condition:
	$a0
}