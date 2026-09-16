rule Win_Trojan_AntiCom_1
{
strings:
	$a0 = { b062ebf3a31706b000a26a01ba6c068b1e6101a06301b44024023c02751a33c9525f8a053c00 }


condition:
	$a0
}