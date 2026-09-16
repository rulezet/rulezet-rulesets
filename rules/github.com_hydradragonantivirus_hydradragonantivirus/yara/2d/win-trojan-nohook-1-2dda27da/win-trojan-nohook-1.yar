rule Win_Trojan_NoHook_1
{
strings:
	$a0 = { b93000f3a4c43e0a004fb085aacd200018020000b43c33c9cd21930e1fb440b93000ba0002cd21b43ecd21 }


condition:
	$a0
}