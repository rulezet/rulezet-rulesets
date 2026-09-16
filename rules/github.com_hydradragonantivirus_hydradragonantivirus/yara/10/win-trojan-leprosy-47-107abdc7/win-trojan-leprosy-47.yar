rule Win_Trojan_Leprosy_47
{
strings:
	$a0 = { cd21e80100c3bb41018a273226060188274381fb58 }


condition:
	$a0
}