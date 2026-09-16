rule Win_Trojan_Bero_3
{
strings:
	$a0 = { ba6801b440cd21b00233d233c9e87700b440b94902ba0001cd21b8003ecd211f5a59e8c000 }


condition:
	$a0
}