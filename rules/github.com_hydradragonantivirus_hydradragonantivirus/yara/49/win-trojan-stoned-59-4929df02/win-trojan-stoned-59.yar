rule Win_Trojan_Stoned_59
{
strings:
	$a0 = { c08ed8a1130431ff31f648b106a31304d3e08ec087064e00a3407db8d70087064c00a33e7d0e1f }


condition:
	$a0
}