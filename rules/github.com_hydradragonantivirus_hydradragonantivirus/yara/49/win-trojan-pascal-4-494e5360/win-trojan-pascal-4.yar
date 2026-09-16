rule Win_Trojan_Pascal_4
{
strings:
	$a0 = { 5e01b82425ba0e03cd21b41aba3201cd }


condition:
	$a0
}