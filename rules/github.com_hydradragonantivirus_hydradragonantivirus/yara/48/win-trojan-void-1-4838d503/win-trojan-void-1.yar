rule Win_Trojan_Void_1
{
strings:
	$a0 = { 01e8a6fd8b1e9a01babc01b90300b4409cfaff1eb707ba0301b9fd08b4409cfaff1eb707b43e }


condition:
	$a0
}