rule Win_Trojan_Sagic_3
{
strings:
	$a0 = { 687474703a2f2fb96578706c8d652eee953e6c07654f6f70a207d3f6eda4eba130ebe8003fa6d083c20be7e4b9b0b10cbc1be05620961111530cc84916ff }


condition:
	$a0
}