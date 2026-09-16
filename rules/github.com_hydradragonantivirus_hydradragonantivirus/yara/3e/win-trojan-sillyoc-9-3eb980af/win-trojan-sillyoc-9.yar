rule Win_Trojan_SillyOC_9
{
strings:
	$a0 = { 01c7049090b402cd1a88361201be1301bf7801b96600f2a4bb7801b96600a01201300743e2fb }


condition:
	$a0
}