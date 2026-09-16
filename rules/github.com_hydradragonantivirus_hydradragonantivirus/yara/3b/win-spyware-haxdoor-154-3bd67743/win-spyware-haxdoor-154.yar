rule Win_Spyware_Haxdoor_154
{
strings:
	$a0 = { 7470733ae8c26fc02f2f38652d676f6c64fc2f7f67bf4d282f0079776964a332311768656967d90dde775d }


condition:
	$a0
}