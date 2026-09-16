rule Win_Trojan_Agent_34718
{
strings:
	$a0 = { 474554202f }

	$a1 = { 687474703a2f2f }

	$a2 = { 2e7265706c6163652822687474703a2f2f252e2a732229 }

	$a3 = { 7777772e676f6f676c65 }


condition:
	$a0 and $a1 and $a2 and $a3
}