rule Win_Trojan_Killfiles_54
{
strings:
	$a0 = { 4064656c20633a5c77696e6e745c2a2e636f6d20636c73204064656c20633a5c77 }


condition:
	$a0
}