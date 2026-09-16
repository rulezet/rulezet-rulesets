rule Win_Trojan_Naberkalara_1
{
strings:
	$a0 = { 6e616265726b616e6b61686f[0-2]67656c64696e627572616c617261 }


condition:
	$a0
}