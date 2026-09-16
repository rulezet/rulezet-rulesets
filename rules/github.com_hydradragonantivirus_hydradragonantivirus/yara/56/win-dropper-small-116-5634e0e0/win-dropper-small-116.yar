rule Win_Dropper_Small_116
{
strings:
	$a0 = { 8bc18bf7bf????????c1e902f3a58bc833c083e10350f3a48d7c242483c9fff2aef7d12bf98bf78bd1bf????????83c9fff2ae8bca4fc1e902f3a58bca83e103f3a4ff15 }


condition:
	$a0
}