rule Win_Trojan_Spanska_7
{
strings:
	$a0 = { 962701b9b4058db640018bfeac9032c2e8eaffe2f7 }


condition:
	$a0
}