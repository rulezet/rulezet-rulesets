rule Win_Trojan_Lamo_4
{
strings:
	$a0 = { 2e72756e2822676f76612e7662732e626174 }


condition:
	$a0
}