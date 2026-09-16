rule Win_Trojan_Agent_34561
{
strings:
	$a0 = { 81fa20522b013bd6f833c1c1efbaf7d28d35f0da400085c53bcbfff050 }


condition:
	$a0
}