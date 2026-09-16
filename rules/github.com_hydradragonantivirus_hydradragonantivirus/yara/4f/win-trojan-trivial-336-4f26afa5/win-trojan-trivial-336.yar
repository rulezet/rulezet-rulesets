rule Win_Trojan_Trivial_336
{
strings:
	$a0 = { b44eba2300cd217227b8023dba9e00cd21b740 }


condition:
	$a0
}