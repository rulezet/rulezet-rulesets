rule Win_Trojan_Beer_14
{
strings:
	$a0 = { 1e0660e8b6ffe961050000000000000000fae8a7ff2ec606d101009c1e06600e1fb82435e8f900062e8f0621022e }


condition:
	$a0
}