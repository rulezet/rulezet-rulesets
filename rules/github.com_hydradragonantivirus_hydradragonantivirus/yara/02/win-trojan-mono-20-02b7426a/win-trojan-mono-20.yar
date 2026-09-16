rule Win_Trojan_Mono_20
{
strings:
	$a0 = { 8bc990908bd28bd28bc9909090909090909090908bc98bd28bc990908bd28bd28bc98bc98bd28bc990908bd28bd28bc98bc98bd28bc99090 }


condition:
	$a0
}