rule Win_Trojan_Einvolk_2
{
strings:
	$a0 = { 02cd211fb43bba9d0203d6cd21b42acd2180fe0b751fb500b80d05b101ba8000cd13fec5 }


condition:
	$a0
}