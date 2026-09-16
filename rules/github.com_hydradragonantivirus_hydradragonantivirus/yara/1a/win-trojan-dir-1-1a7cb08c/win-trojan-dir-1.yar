rule Win_Trojan_Dir_1
{
strings:
	$a0 = { 402e8b1e7d03b90600ba9503cd21b802422e8b1e7d0331c931d2cd21 }


condition:
	$a0
}