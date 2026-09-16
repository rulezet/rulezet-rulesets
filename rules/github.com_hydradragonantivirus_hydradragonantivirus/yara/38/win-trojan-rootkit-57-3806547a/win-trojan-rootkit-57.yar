rule Win_Trojan_Rootkit_57
{
strings:
	$a0 = { 8bff558bec83ec0c680870000068000e01 }

	$a1 = { 7369626572696132 }

	$a2 = { 5c6d333265737663516f737417657865 }


condition:
	$a0 and $a1 and $a2
}