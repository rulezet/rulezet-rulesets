rule Win_Trojan_Mono_22
{
strings:
	$a0 = { 8b65e88bc98bd28bc990908bd28bd28bc968 }

	$a1 = { 8bc98bd28bc99090 }

	$a2 = { 8bc98bd28bc99090 }


condition:
	$a0 and $a1 and $a2
}