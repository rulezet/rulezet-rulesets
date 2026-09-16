rule Win_Trojan_Trojan_290
{
strings:
	$a0 = { c1019a00005f019ae504f0009a9900e4009a4c0856005589e5c6065a01009a3b09c101bf6c021e579a940cc101 }


condition:
	$a0
}