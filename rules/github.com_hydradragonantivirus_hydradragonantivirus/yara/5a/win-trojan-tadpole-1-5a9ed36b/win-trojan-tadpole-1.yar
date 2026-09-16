rule Win_Trojan_Tadpole_1
{
strings:
	$a0 = { 16e80a2e8926ea0afb9c2eff1eec005dc3b440e8e6ff9c5156be0000b920002e880446e2fa5e }


condition:
	$a0
}