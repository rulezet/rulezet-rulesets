rule Win_Trojan_AVCS_6
{
strings:
	$a0 = { e800005b81eb0c018beb8db62d01568b961802b972008bfe84cefcad33c2ab3affe2f8c3 }


condition:
	$a0
}