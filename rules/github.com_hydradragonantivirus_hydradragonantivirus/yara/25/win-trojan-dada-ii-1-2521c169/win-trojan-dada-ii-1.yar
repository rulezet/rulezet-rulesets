rule Win_Trojan_Dada_II_1
{
strings:
	$a0 = { f3a4b8baabcd2f3ddada7503e98c008bfbb82135cd212e }


condition:
	$a0
}