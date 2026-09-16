rule Win_Trojan_Shutdown_2
{
strings:
	$a0 = { 2180fe037548ba0301b409cd21ba3701b409cd2133c0cd13b80903b90101ba8000cd13fec680fe0575f7fec232 }


condition:
	$a0
}