rule Win_Trojan_Anti_9
{
strings:
	$a0 = { 21b998020e1fba9803b4402e8b1e6e03cd212e8b1e6e03b43ecd211f5a521e2e8b0e6c03b80143 }


condition:
	$a0
}