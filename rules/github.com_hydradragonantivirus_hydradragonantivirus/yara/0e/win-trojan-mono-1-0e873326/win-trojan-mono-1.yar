rule Win_Trojan_Mono_1
{
strings:
	$a0 = { a406e800005983c10651cb2e8c4f048d4ff6f3a42e8c }


condition:
	$a0
}