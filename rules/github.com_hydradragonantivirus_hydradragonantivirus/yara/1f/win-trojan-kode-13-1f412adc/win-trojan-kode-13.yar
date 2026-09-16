rule Win_Trojan_Kode_13
{
strings:
	$a0 = { cd213d0101744eb44eba5a01cd21b443b000ba9e00cd21b443b00181e1fe00cd21 }


condition:
	$a0
}