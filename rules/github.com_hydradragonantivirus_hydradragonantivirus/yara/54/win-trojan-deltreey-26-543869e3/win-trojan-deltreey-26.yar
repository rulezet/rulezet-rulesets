rule Win_Trojan_DeltreeY_26
{
strings:
	$a0 = { 44454c54524545000b202f(79|59)20633a5c2a2e2a }


condition:
	$a0
}