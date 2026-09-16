rule Win_Trojan_Chameleon_4
{
strings:
	$a0 = { b90c07b87b1df8f933db90bf3201f9f890fcfb314900f9f890fbfc9047e2ef }


condition:
	$a0
}