rule Win_Trojan_Saturday14_1
{
strings:
	$a0 = { 80fcde7502b4df3d004b7403e9b10150 }


condition:
	$a0
}