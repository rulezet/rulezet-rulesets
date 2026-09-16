rule Win_Trojan_Australian_9
{
strings:
	$a0 = { 8c065b018cc88ed8b82125ba9401cd21 }


condition:
	$a0
}