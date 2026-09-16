rule Win_Trojan_Grade_1
{
strings:
	$a0 = { cd211e06e800005d83ed0a1e5083fbfe74598cd848488ed88a1e1000c60610004d832e130049832e220049a122 }


condition:
	$a0
}