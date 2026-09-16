rule Win_Spyware_VB_368
{
strings:
	$a0 = { 6a04516a046a008d55e468443c400052c745e001000000ffd6 }


condition:
	$a0
}