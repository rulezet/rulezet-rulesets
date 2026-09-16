rule Win_Trojan_Rmdc_3
{
strings:
	$a0 = { fc4b757c0e1fb86e022ea35d021fb80043cd21726b2e89 }


condition:
	$a0
}