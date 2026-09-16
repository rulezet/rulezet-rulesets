rule Win_Trojan_Malaria_1
{
strings:
	$a0 = { 8ec050b86f0150b80202bb0001b94c4dfec6cd13cb33c08ec0be3604bf007c5057b10cf32e }


condition:
	$a0
}