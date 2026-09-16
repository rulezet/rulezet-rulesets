rule lzari__StartModel___32_lil_AND_
{
strings:
	$a0 = { 3a010000[0-20]10270000[0-20]c8000000 }

condition:
	$a0
}