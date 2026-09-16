rule Win_Trojan_Hammer_2
{
strings:
	$a0 = { 0e07bb0010cd21b448bb2000cd212ea30701b41aba0b01cd212ea1090150b44eba1102b90000cd21ba0b0183c21e }


condition:
	$a0
}