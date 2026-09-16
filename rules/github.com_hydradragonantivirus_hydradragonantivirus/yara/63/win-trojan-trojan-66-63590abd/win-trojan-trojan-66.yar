rule Win_Trojan_Trojan_66
{
strings:
	$a0 = { b433e800005d81ed05018db6????bf000257a5a4c686??????b41a8d96????cd21b447b200 }


condition:
	$a0
}