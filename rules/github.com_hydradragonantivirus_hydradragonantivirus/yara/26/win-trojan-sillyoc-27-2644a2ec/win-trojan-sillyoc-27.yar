rule Win_Trojan_SillyOC_27
{
strings:
	$a0 = { 40eb0290e8b601eb0290e8b200eb0290e88aeaeb0290e8b1f79090eb0290e8cd21eb0290e8b43e }


condition:
	$a0
}