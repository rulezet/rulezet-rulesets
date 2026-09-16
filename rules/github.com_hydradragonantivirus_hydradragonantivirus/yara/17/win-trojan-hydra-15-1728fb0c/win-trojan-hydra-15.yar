rule Win_Trojan_Hydra_15
{
strings:
	$a0 = { 9af59c86f5bf9a9d9bf5b2949981 }


condition:
	$a0
}