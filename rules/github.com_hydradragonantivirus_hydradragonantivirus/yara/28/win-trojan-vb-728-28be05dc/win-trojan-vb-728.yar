rule Win_Trojan_VB_728
{
strings:
	$a0 = { 5368616e6961 }

	$a1 = { 4b0049004c004c }

	$a2 = { 63003a005c004600720075006e006c006f0067002e007400780074 }

	$a3 = { 47466c656d696e67 }


condition:
	$a0 and $a1 and $a2 and $a3
}