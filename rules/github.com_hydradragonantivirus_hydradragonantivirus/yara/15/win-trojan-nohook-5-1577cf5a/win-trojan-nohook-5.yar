rule Win_Trojan_NoHook_5
{
strings:
	$a0 = { bf0002b95200f3a4c43e0a004fb085aacd200018020000b43c33c9cd21930e1fb440b95200ba0002cd21b43ecd21cf }


condition:
	$a0
}