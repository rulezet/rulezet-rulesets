rule Win_Trojan_E_19
{
strings:
	$a0 = { 29ff4d494b452e26fa8cc82e01066c008cdabb24008ec333ff33f68ed8b98000fcf3a5ea2b0024008bec8b4efe }


condition:
	$a0
}