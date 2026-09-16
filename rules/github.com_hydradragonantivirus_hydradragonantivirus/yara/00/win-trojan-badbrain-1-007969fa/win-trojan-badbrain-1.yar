rule Win_Trojan_Badbrain_1
{
strings:
	$a0 = { 3451b9ac02be33018bfefcad33060201abe2f859c3ba00018b1e1803b97901e8dfffb80040cd21 }


condition:
	$a0
}