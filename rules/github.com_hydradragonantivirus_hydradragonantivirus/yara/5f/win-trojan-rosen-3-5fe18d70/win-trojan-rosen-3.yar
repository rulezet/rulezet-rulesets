rule Win_Trojan_Rosen_3
{
strings:
	$a0 = { 0500108ec0be000133ffb98300f3 }


condition:
	$a0
}