rule Win_Trojan_Fricker_1
{
strings:
	$a0 = { b90100bad000cd213e803ed000247514b43ecd213e80 }


condition:
	$a0
}