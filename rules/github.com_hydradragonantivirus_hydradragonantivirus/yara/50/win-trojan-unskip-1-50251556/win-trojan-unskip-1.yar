rule Win_Trojan_Unskip_1
{
strings:
	$a0 = { 8f06e4060e1f8c0ef7069c9cba6a0833c08ec0b425b00326ff1e8400ba6a08b00126ff1e84001e078b16e60681fa }


condition:
	$a0
}