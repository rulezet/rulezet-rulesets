rule Win_Trojan_Cancerbero_1
{
strings:
	$a0 = { cd210e0e1f07e800005d81ed0d01b92b008dbeb102be8000f3a4fcb90400bf00018db6dc02f3a450558becc7 }


condition:
	$a0
}