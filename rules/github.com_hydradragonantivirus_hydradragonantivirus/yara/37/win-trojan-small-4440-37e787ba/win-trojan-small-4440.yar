rule Win_Trojan_Small_4440
{
strings:
	$a0 = { 6853530400b8??cfbdfff7d089e28902 }


condition:
	$a0
}