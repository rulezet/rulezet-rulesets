rule Win_Spyware_Banker_3082
{
strings:
	$a0 = { beffbe8b5076cad950fb6afe0f4884afc5e447ffa228f1ef99e4440e193ae64a0ffc16cf94b127d3191742d39f27b8356f6eefaddfe2a79495d84057d848 }


condition:
	$a0
}