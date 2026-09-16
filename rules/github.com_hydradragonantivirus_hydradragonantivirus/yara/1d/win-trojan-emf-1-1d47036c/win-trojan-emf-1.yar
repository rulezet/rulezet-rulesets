rule Win_Trojan_EMF_1
{
strings:
	$a0 = { b4408bd583ea03b99301cd21e80100c3b94c018db6 }


condition:
	$a0
}