rule Win_Trojan_Autorun_373
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e64203d20617571782e657865 }


condition:
	$a0
}