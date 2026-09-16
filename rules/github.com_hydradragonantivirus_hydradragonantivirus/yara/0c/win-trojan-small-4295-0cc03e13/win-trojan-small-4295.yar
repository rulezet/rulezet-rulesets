rule Win_Trojan_Small_4295
{
strings:
	$a0 = { 8d056402400083c004ffd06a00e800000000ff25f80140004002 }


condition:
	$a0
}