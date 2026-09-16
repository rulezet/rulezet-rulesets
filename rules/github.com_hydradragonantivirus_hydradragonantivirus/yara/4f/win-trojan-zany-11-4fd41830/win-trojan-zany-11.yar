rule Win_Trojan_Zany_11
{
strings:
	$a0 = { 03be7e0003f5bf150103fdb90300f3a4bb000053eb049083c306ba820003d3b44e03d5b92000cd217236ba9e00 }


condition:
	$a0
}