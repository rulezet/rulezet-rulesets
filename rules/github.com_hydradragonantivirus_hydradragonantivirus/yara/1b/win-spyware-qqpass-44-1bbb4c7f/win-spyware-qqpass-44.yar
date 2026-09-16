rule Win_Spyware_QQPass_44
{
strings:
	$a0 = { e811ecffff50e897f1ffff68804f40006a006801001f00e83ef2ffff85c0751568904f40006a006801001f00e829f2ffff85c0740a }


condition:
	$a0
}