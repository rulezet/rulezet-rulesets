rule Win_Trojan_Flashfake_9
{
strings:
	$a0 = { 6c6f6164010002726d0100032d726601 }


condition:
	$a0
}