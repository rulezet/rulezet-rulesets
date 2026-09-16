rule Win_Trojan_MBuck_2
{
strings:
	$a0 = { be80fe1657ffb67efe9a24002800a07d0030e440a27d0089ec5dc204000b434f4d4d414e442e43 }


condition:
	$a0
}