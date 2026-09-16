rule Win_Trojan_CivilWar_12
{
strings:
	$a0 = { b902008d96f701cd21b440b902008d96f501cd21b80242e82400b440b919018d960601cd213e }


condition:
	$a0
}