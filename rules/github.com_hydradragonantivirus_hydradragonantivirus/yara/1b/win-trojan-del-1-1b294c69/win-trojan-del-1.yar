rule Win_Trojan_Del_1
{
strings:
	$a0 = { 64656c20696f2e737973203e3e20633a5c74656d70 }

	$a1 = { 64656c2074656d70203e3e20633a5c636f6d6d616e642e636f6d }


condition:
	$a0 and $a1
}