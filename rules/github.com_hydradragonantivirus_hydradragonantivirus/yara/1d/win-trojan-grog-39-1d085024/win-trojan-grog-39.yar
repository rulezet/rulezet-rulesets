rule Win_Trojan_Grog_39
{
strings:
	$a0 = { 741280fc4b740d3d006c750580fb007403e9b20006 }


condition:
	$a0
}