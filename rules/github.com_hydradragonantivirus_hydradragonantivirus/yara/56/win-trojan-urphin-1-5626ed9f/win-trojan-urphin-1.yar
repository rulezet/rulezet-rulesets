rule Win_Trojan_Urphin_1
{
strings:
	$a0 = { e800005e81ee12058beeb8aaaacd213dbbbb7503e9e000b80043cd2f3c807524b81043cd2f2e899c }


condition:
	$a0
}