rule Win_Trojan_Riot_19
{
strings:
	$a0 = { b5008d964801cd21b80042b90000ba0000cd21b440b905008d96f801cd21fe86ec01b43ecd }


condition:
	$a0
}