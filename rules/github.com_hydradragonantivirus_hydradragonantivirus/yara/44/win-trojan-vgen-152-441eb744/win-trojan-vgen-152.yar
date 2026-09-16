rule Win_Trojan_VGEN_152
{
strings:
	$a0 = { f08ec0ba0000b90100b402b001bb0080cd13e8890690909001d831c8e8df0e438b07bee0f1c1d284b511ebe80d13 }


condition:
	$a0
}