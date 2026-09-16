rule Win_Trojan_Stoned_22
{
strings:
	$a0 = { c08ed8fa8ed0bc007cfbc4064c00a3207c8c06227ca1130448a31304b106d3e08ec0c7064c002b }


condition:
	$a0
}