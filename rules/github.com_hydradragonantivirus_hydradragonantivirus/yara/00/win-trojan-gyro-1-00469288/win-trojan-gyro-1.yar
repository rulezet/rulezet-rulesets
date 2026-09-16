rule Win_Trojan_Gyro_1
{
strings:
	$a0 = { 1fc70621013e01bd0003316e00a11f013146004d81fd3e }


condition:
	$a0
}