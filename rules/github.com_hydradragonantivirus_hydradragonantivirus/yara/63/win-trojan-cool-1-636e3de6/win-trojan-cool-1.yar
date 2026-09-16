rule Win_Trojan_Cool_1
{
strings:
	$a0 = { 023dad0e750ab801c0cfe94101e936013d004b75f550 }


condition:
	$a0
}