rule Win_Trojan_Gefetroe_1
{
strings:
	$a0 = { 4746445f4d41494e5f4c4f4144 }

	$a1 = { 5752495445494e4155544f5354415254 }

	$a2 = { 4746445f4d41494e5f434c4f5345 }


condition:
	$a0 and $a1 and $a2
}