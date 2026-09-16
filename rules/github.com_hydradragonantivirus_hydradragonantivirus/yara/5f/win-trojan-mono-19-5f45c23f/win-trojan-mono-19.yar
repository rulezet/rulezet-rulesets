rule Win_Trojan_Mono_19
{
strings:
	$a0 = { 90908bd28bd28bc98bc98bd28bc990908bd28bd28bc98bc98bd28bc99090 }


condition:
	$a0
}