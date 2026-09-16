rule Win_Trojan_Trojan_163
{
strings:
	$a0 = { 013d03007511e84a013d0b007509ba4c01b409cd21ebf7b84400908ec090bf00018bf7b95d01f3a48ed9be8400bf5d02ba6a01ad3bc27409aba5061fb821 }


condition:
	$a0
}