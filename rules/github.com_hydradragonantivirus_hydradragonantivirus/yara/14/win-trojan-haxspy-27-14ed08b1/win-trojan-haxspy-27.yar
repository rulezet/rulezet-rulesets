rule Win_Trojan_Haxspy_27
{
strings:
	$a0 = { 2e73796d610a63443428137d7f8867ffb653741e2e6d6361666565136f77207e80dd996164 }


condition:
	$a0
}