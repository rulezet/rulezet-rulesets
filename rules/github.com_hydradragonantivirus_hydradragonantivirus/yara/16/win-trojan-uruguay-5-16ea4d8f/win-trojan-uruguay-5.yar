rule Win_Trojan_Uruguay_5
{
strings:
	$a0 = { 3b9e36d90d2dfc9814d903147efa9b63efc60730fd82a53b062cfae07275865017d8c82cfabe7265 }


condition:
	$a0
}