rule Win_Trojan_HXH_2
{
strings:
	$a0 = { 05b4fecd2180fcaa7550803ecf0601742b8cc82b062f }


condition:
	$a0
}