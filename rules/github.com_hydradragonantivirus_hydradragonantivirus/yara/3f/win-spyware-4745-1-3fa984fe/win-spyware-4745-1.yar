rule Win_Spyware_4745_1
{
strings:
	$a0 = { 81c6957bb80c5481ee957bb80c893424 }


condition:
	$a0
}