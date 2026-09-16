rule Win_Trojan_Rmdc_2
{
strings:
	$a0 = { 4b7403e95d010e1fb860022ea34f021fb80043cd2173 }


condition:
	$a0
}