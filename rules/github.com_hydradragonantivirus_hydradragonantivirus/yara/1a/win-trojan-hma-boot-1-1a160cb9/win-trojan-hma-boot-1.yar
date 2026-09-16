rule Win_Trojan_HMA_Boot_1
{
strings:
	$a0 = { d1e664b0ffe660bb007c0efc1fc47744b9fe018bfe0e530656f3a45ee83000b1fff3a5be6800b8 }


condition:
	$a0
}