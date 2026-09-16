rule Win_Trojan_Vundo_18
{
strings:
	$a0 = { 60e8cc170000faab08a1c64d691e1d000020d99e1c93 }


condition:
	$a0
}