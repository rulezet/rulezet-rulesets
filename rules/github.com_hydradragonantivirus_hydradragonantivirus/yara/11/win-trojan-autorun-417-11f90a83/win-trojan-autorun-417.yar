rule Win_Trojan_Autorun_417
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d72656379636c655c }

	$a1 = { 2e657865 }


condition:
	$a0 and $a1
}