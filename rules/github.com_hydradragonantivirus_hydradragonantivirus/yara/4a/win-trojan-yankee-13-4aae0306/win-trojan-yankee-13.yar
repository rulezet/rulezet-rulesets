rule Win_Trojan_Yankee_13
{
strings:
	$a0 = { 0c4b53090c345002b879ba3079c88acb0c499680a6 }


condition:
	$a0
}