rule Win_Trojan_Delfiles_3
{
strings:
	$a0 = { 64656c202f46202f51202f53202573797374656d726f6f74255c }


condition:
	$a0
}