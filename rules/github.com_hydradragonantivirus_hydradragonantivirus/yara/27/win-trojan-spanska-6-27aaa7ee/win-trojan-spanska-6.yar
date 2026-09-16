rule Win_Trojan_Spanska_6
{
strings:
	$a0 = { 8a962601b9ac058db63f018bfeac9032c2e8eaffe2f7 }


condition:
	$a0
}