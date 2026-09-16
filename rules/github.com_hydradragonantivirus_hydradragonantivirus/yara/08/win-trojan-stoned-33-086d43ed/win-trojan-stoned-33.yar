rule Win_Trojan_Stoned_33
{
strings:
	$a0 = { c70604000000b80103b90700ba8000cd13b8010333dbb90100cd13 }


condition:
	$a0
}