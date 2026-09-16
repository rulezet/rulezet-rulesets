rule Win_Trojan_AAEH_1
{
strings:
	$a0 = { 787776656c7a7a6a7262786f }

	$a1 = { b5f9f8f8e9e6bcb7b6cdff936fc5eff2fbf7f3f6f3f12c00000000000000000090f5bde7f9bae9e9f8eae6b9e4f5f798 }


condition:
	$a0 and $a1
}