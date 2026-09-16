rule Win_Trojan_SillyC_166
{
strings:
	$a0 = { 4d4d4dbe1d0103f5bffc0057b8f3aaabb8eb00aba4a5ba3c0103d58bf2b41acd21bf2e0103fdc645fe43bb200103dd }


condition:
	$a0
}