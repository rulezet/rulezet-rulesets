rule Win_Trojan_NoSmoking_1
{
strings:
	$a0 = { 37db712d7938f670bff7cabff643fbfa4eba37db42fbada3a037db1158ad9b8e9f88da9e9f8e9f99 }


condition:
	$a0
}