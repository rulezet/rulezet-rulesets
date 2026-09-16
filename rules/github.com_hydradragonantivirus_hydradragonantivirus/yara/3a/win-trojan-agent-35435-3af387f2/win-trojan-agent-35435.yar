rule Win_Trojan_Agent_35435
{
strings:
	$a0 = { 6633c0740b110068600b206c6e1a0a5d56 }

	$a1 = { 62486f4755424b2662556f2462735a3f41306d3573515a2255 }


condition:
	$a0 and $a1
}