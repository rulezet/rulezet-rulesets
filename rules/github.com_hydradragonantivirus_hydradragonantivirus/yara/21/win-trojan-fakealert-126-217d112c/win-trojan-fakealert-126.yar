rule Win_Trojan_Fakealert_126
{
strings:
	$a0 = { 558bec81ece00000000f2de3530f2dd30f310f2dd18bd80f }

	$a1 = { 4778285579746f23526d7d683f53 }


condition:
	$a0 and $a1
}