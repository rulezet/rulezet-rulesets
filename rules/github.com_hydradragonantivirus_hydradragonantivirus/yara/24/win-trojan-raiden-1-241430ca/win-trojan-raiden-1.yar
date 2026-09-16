rule Win_Trojan_Raiden_1
{
strings:
	$a0 = { 06508e1e2c00b9000433f6833c00740346e2f883c6048bd61e061fbe8300b9090033c08bc3ac03d8e2fb1f81fbba02 }


condition:
	$a0
}