rule Win_Trojan_Jasmin_1
{
strings:
	$a0 = { 2180fd00750ab002b90500ba0000cd26b44eba000131c9cd21ba9e00bf9e00b000 }


condition:
	$a0
}