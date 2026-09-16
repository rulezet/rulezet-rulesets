rule Win_Trojan_SillyC_154
{
strings:
	$a0 = { 0156fa609cb42acd2180fe037517fb8cc88ec0bb1902b403b002b500b101b600b280cd13fa9d }


condition:
	$a0
}