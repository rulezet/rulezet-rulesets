rule Win_Trojan_Rbot_59
{
strings:
	$a0 = { 558bec83c4ec33c08945ecb8402f4000e81fedffff33c055 }

	$a1 = { 616e6479 }


condition:
	$a0 and $a1
}