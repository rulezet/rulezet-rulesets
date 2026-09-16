rule Win_Trojan_CMAKER_658554_Multiple_viruses_2_1
{
strings:
	$a0 = { b860a6bad64d3bc473678bc42d440325f0ff8bf8b9a200be7c01fcf3a58bd8b104d3eb8cd903d95333db53cb03011a45 }


condition:
	$a0
}