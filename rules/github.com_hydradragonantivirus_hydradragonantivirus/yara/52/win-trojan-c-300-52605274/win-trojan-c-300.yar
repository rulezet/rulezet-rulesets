rule Win_Trojan_C_300
{
strings:
	$a0 = { 558bec6aff68e0e8420068b407410064a100000000506489 }

	$a1 = { 47414d454f424a2e544258 }

	$a2 = { 426c696e6453696465 }


condition:
	$a0 and $a1 and $a2
}