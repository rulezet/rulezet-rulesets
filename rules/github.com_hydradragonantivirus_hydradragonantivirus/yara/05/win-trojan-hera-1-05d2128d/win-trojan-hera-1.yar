rule Win_Trojan_Hera_1
{
strings:
	$a0 = { a5a5b8ff2ccd213dad2b7503e90300e81000bcecff5d5f }


condition:
	$a0
}