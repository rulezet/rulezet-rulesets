rule Win_Trojan_Farenheit_2
{
strings:
	$a0 = { 062001cd3b1e2c00cd3da12c00cdeca0cd81be3001cd96cdeccccd3b066c01cded2ca32c00cd }


condition:
	$a0
}