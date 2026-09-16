rule Win_Trojan_Mark13_1
{
strings:
	$a0 = { a4b800908ec00e1fbe0000bf0000b90001f3a4b800908ed8b82125babf01cd210e1f0e07be1001 }


condition:
	$a0
}