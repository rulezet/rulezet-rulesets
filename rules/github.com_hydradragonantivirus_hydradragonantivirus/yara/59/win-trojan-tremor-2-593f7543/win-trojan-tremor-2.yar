rule Win_Trojan_Tremor_2
{
strings:
	$a0 = { e485c1bea004bd82f736311c81f3670646fb464577f3 }


condition:
	$a0
}