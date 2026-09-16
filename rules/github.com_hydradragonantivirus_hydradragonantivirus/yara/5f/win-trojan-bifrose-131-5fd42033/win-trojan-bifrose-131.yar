rule Win_Trojan_Bifrose_131
{
strings:
	$a0 = { 75578d45e48b15989749008b12e8cd6bf7ff8b4de4ba010000008b45fce811fdffff84c00f855b010000 }


condition:
	$a0
}