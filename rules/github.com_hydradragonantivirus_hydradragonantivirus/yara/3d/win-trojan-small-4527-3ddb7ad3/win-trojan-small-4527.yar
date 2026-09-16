rule Win_Trojan_Small_4527
{
strings:
	$a0 = { bd06324200ba60d842008b1affd301d5 }


condition:
	$a0
}