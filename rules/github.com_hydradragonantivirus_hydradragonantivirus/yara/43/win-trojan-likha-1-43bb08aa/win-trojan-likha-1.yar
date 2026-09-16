rule Win_Trojan_Likha_1
{
strings:
	$a0 = { f2bab0c2fab0331a12caea2abab0ebba0aba7abac2b02abab0dbbac2fad2bad0b05068696c697070696e6573 }


condition:
	$a0
}