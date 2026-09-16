rule Win_Trojan_Rmdc_4
{
strings:
	$a0 = { 757d0e1fb86f022ea35e021fb80043cd21726c2e89 }


condition:
	$a0
}