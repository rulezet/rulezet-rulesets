rule Win_Trojan_SillyOC_25
{
strings:
	$a0 = { 40eb0290e9b601eb0290e9b200eb0290e98aeaeb0290e9b1f79090eb0290e9cd21eb0290e9b43e }


condition:
	$a0
}