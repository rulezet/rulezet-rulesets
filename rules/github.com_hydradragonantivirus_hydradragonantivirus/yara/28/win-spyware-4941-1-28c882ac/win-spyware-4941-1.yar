rule Win_Spyware_4941_1
{
strings:
	$a0 = { 81c31d1fc83d5481eb1d1fc83d891c24 }


condition:
	$a0
}