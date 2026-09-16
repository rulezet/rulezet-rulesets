rule Win_Trojan_Small_4282
{
strings:
	$a0 = { 3aca81e5ea67e2000f8b38000000900f8d3500000050588ac181f7d1b55801 }


condition:
	$a0
}