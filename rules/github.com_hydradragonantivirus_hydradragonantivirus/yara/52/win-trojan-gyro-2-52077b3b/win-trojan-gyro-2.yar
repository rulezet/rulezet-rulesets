rule Win_Trojan_Gyro_2
{
strings:
	$a0 = { 0140a32301b440b90002ba0001cd21c70621012802ebca }


condition:
	$a0
}