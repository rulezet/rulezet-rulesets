rule Win_Trojan_Teller_1
{
strings:
	$a0 = { b50bb81035cd212e891ea40b062e8c06a60bba110c33c050b81025cd2158072eff368005e9a30b }


condition:
	$a0
}