rule Win_Trojan_Crypted_3
{
strings:
	$a0 = { 68??????00e8??????00 }

	$a1 = { 8b74242c89e581ecc000000089e70375008a060fb6c0????01ff2485 }


condition:
	$a0 and $a1
}