rule Win_Trojan_Dialer_64
{
strings:
	$a0 = { 6973646e000000006d6f64656d000000302c000030000000506f726e2564 }


condition:
	$a0
}