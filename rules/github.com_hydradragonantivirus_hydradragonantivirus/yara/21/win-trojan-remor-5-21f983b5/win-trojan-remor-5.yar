rule Win_Trojan_Remor_5
{
strings:
	$a0 = { 02a3fa02a1fc02a31f038a262f038b16fa0203161f0381c22001cd2183c21e8916210389 }


condition:
	$a0
}