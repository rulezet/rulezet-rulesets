rule Win_Trojan_Fasolo_2
{
strings:
	$a0 = { b080b500b101b600b280bb0000cd13fbb010e670b000 }


condition:
	$a0
}