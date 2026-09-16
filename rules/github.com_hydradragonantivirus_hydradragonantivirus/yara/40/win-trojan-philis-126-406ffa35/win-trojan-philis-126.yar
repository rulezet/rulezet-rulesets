rule Win_Trojan_Philis_126
{
strings:
	$a0 = { 33d733d76081c72377000081ef2377 }


condition:
	$a0
}