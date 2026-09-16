rule Win_Trojan_Format_1
{
strings:
	$a0 = { b402b003b503b10ab600b20226bbd007cd0db403b003b500b100b600b20226bbd007cd0db421 }


condition:
	$a0
}