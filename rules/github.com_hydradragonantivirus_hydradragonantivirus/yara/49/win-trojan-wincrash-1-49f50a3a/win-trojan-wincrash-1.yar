rule Win_Trojan_Wincrash_1
{
strings:
	$a0 = { 2877696e646f772e616c657274282220bbb6d3adc4e3c0b4b5bdd7a8ceaac4e3b6f8d7f6b5c4d5fbc8cbcdf8d2b3a3a120222929 }


condition:
	$a0
}