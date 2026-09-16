rule Win_Trojan_CyberTech_14
{
strings:
	$a0 = { 69727573e2fa50e80000582d1a0189c58db6de02bf0001a5a4b41aba00f9cd21b44e8d96d80233c9cd21730db41aba }


condition:
	$a0
}