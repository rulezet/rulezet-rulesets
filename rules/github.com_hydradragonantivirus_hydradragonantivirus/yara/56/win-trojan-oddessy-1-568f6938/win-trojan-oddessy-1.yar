rule Win_Trojan_Oddessy_1
{
strings:
	$a0 = { 03cd21b9d107ba6e02b42bcd21ba4f03b90200b44ecd21b44fba4f03cd21b443ba9e00b000cd21b100b44390 }


condition:
	$a0
}