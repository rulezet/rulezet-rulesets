rule Win_Trojan_Escort_1
{
strings:
	$a0 = { 3ccd218bd8b197ba0001b440cd21b43ecd21f8b44febaebb9701b104d3ebb44acd21be9701cd2e }


condition:
	$a0
}