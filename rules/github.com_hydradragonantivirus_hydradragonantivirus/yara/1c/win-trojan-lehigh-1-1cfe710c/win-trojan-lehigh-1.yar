rule Win_Trojan_Lehigh_1
{
strings:
	$a0 = { 505380fc4b740880fc4e7403e977018b }


condition:
	$a0
}