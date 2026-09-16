rule Win_Trojan_CyberTech_13
{
strings:
	$a0 = { 0e0189c58db6af02bf0001a5a4b41aba00f9cd21b44e8d96a90233c9cd21730db41aba8000cd21bb00015853c3b800 }


condition:
	$a0
}