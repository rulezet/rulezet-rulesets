rule Win_Trojan_Lokjaw_2
{
strings:
	$a0 = { bf00018db6????b90600f3a4b82c2ccd213dcd0d745b8cc8488ed8 }


condition:
	$a0
}