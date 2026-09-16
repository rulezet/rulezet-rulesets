rule Win_Trojan_Justice_2
{
strings:
	$a0 = { 83c4089e9c83ec0658cf3cff7504 }


condition:
	$a0
}