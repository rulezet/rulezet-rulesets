rule Win_Trojan_QRabid_3
{
strings:
	$a0 = { 2e00000000b8004ccd21b435b013cd21891e53018c065501b425b013ba5701cd21ba5c01cd27 }


condition:
	$a0
}