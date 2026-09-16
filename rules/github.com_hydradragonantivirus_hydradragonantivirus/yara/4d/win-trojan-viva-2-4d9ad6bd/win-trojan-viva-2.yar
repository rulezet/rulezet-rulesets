rule Win_Trojan_Viva_2
{
strings:
	$a0 = { 8d966c033e2ecd2106b821353ecd21899e74038c86760307b40232d2e82a02b208e82502b4 }


condition:
	$a0
}