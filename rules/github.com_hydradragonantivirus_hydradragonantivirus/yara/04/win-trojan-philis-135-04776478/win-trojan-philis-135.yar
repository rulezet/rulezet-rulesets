rule Win_Trojan_Philis_135
{
strings:
	$a0 = { 78037901eb6057e8000000005f5fe8000000005381 }


condition:
	$a0
}