rule Win_Trojan_Trivial_486
{
strings:
	$a0 = { 05ffb1f7d033c9ba8d01cd217273b8000005febcf7d0b90000ba9e00cd217261b8000005fdc2f7d0ba9e00cd21 }


condition:
	$a0
}