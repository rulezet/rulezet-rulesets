rule Win_Trojan_Delsys_15
{
strings:
	$a0 = { 61727261792822633a5c5c }

	$a1 = { 5c5c77696e2e696e69 }

	$a2 = { 66312e64656c6574652829[0-3]616c65727428226261746d616e }


condition:
	$a0 and $a1 and $a2
}