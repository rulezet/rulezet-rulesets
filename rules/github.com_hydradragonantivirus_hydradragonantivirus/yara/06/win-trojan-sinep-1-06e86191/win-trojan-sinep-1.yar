rule Win_Trojan_Sinep_1
{
strings:
	$a0 = { f32ea4fb80fc4b743880fc4c740980fc3174040ae475 }


condition:
	$a0
}