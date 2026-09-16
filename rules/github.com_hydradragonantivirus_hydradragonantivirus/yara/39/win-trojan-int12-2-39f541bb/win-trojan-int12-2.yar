rule Win_Trojan_Int12_2
{
strings:
	$a0 = { 33c0b3138ed8a34800b704b106ff0f8b0733dbd3e0a34a008ec0b9124fb80102cd13e964fe }


condition:
	$a0
}