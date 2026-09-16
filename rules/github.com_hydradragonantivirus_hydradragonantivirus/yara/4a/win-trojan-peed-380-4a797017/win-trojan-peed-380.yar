rule Win_Trojan_Peed_380
{
strings:
	$a0 = { 89fa81c24155000081fa41550000745a81fae1ae00007f526a00e85c00000052 }


condition:
	$a0
}