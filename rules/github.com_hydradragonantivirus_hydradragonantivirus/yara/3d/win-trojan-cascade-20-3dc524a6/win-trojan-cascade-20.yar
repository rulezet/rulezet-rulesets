rule Win_Trojan_Cascade_20
{
strings:
	$a0 = { e800005d83ed052e807e0020740f8dbe1f00b9f902310d313d474975f8 }


condition:
	$a0
}