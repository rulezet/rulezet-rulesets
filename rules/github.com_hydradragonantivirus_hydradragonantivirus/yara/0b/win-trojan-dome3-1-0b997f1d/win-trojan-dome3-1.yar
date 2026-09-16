rule Win_Trojan_Dome3_1
{
strings:
	$a0 = { bb8d0290cd21bcb11290be7b02cd2e508cc88ed88ec0 }


condition:
	$a0
}