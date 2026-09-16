rule Win_Trojan_Vgen_126
{
strings:
	$a0 = { 575652515350b8cdabcd213defcd7405e81c0090908cc88ed82b063000a32e00585b595a5e5f1f07ea000000001f }


condition:
	$a0
}