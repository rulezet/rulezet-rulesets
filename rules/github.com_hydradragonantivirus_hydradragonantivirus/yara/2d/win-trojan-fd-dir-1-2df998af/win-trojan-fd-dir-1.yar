rule Win_Trojan_FD_Dir_1
{
strings:
	$a0 = { 6f009a000009005589e5b800019a7c026f0081ec00019a00006b009aa1076f00bf00000e579aff076f008dbe00 }


condition:
	$a0
}