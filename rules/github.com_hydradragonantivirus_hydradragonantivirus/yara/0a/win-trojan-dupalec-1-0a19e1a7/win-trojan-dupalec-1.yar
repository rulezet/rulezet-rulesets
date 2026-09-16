rule Win_Trojan_Dupalec_1
{
strings:
	$a0 = { fd0000eb0a838600fd01839602fd008dbe54fe1657bf2c021e57b8000850bf28021e579ae1 }


condition:
	$a0
}